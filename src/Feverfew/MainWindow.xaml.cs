using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;

namespace Feverfew
{
    public partial class MainWindow : Window
    {
        private const int DwmUseDarkMode = 20;
        private const int DwmBackdropType = 38;
        private const int BackdropMica = 2;
        private const int FirstBuildWithBackdrop = 22621;
        private const double MaximizedInset = 8;

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr window, int attribute, ref int value, int size);

        private readonly ScanOptions options;
        private readonly bool limited;
        private ScanResult result;
        private TaskCompletionSource<bool> question;
        private readonly System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<Fix, TextBlock>> statusLines = new System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<Fix, TextBlock>>();
        private bool tipsLoaded;
        private bool scanStarted;
        private UpdateInfo launchUpdate;
        private string verifiedSetup;

        public MainWindow(ScanOptions options, bool limited)
        {
            this.options = options;
            this.limited = limited;
            InitializeComponent();

            var version = Updater.CurrentVersion().ToString();
            TitleVersion.Text = version;
            VersionText.Text = "Feverfew " + version;
            Identifiers.IsChecked = options.IncludeIdentifiers;
            AccessText.Text = limited ? "Limited" : "Administrator";
            AccessText.Foreground = (Brush)FindResource(limited ? "WarningText" : "Accent");
            AccessDetail.Text = limited ? "Some checks will be skipped" : "Full scan available";
            LimitedBar.Visibility = limited ? Visibility.Visible : Visibility.Collapsed;
            AutoUpdate.IsChecked = UpdateSettings.AutoUpdate;
            NotifyOnLaunch.IsChecked = UpdateSettings.NotifyOnLaunch || AutoUpdate.IsChecked == true;
            NotifyOnLaunch.IsEnabled = AutoUpdate.IsChecked != true;
            Loaded += async (s, e) => await CheckAtLaunch();

            foreach (var fix in Fixes.All) RepairList.Children.Add(BuildFixRow(fix, RepairStatus, "Run"));
            foreach (var fix in Fixes.Gaming) GamingList.Children.Add(BuildFixRow(fix, GamingStatus, "Apply"));
            SourceInitialized += (s, e) => ApplyBackdrop();
            StateChanged += (s, e) => Root.Margin = new Thickness(WindowState == WindowState.Maximized ? MaximizedInset : 0);
            Closed += (s, e) => Environment.Exit(0); // an abandoned scan step may still be running on a background thread
        }

        // Mica needs Windows 11 22H2 or later. Older versions keep the solid dark background.
        private void ApplyBackdrop()
        {
            var handle = new WindowInteropHelper(this).Handle;
            int on = 1;
            DwmSetWindowAttribute(handle, DwmUseDarkMode, ref on, sizeof(int));
            if (Environment.OSVersion.Version.Build < FirstBuildWithBackdrop) return;

            int mica = BackdropMica;
            if (DwmSetWindowAttribute(handle, DwmBackdropType, ref mica, sizeof(int)) != 0) return;
            Background = Brushes.Transparent;
            HwndSource.FromHwnd(handle).CompositionTarget.BackgroundColor = Colors.Transparent;
        }

        private void Nav_Checked(object sender, RoutedEventArgs e)
        {
            if (ScanPage == null) return; // fires during startup, before the pages exist
            ScanPage.Visibility = sender == NavScan ? Visibility.Visible : Visibility.Collapsed;
            RepairPage.Visibility = sender == NavRepair ? Visibility.Visible : Visibility.Collapsed;
            GamingPage.Visibility = sender == NavGaming ? Visibility.Visible : Visibility.Collapsed;
            UpdatesPage.Visibility = sender == NavUpdates ? Visibility.Visible : Visibility.Collapsed;
            if (sender == NavGaming) RefreshPage(Fixes.Gaming, true);
            if (sender == NavRepair) RefreshPage(Fixes.All, false);
        }

        private async void RefreshPage(Fix[] page, bool tips)
        {
            await RefreshStatusLines(page);
            if (tips) await LoadGraphicsTips();
        }

        // Re-read on every visit, so a change made in an administrator window shows when the user comes back.
        private async Task RefreshStatusLines(Fix[] page)
        {
            foreach (var pair in statusLines.Where(p => page.Contains(p.Key)).ToList())
            {
                var fix = pair.Key;
                var line = pair.Value;
                line.Text = await Task.Run(() =>
                {
                    try { return fix.Status(); }
                    catch (Exception) { return "Couldn't read the current setting"; }
                });
            }
        }

        private async Task LoadGraphicsTips()
        {
            if (tipsLoaded) return;
            tipsLoaded = true;
            try
            {
                var tips = await Task.Run(() => Collectors.GamingCollector.TipsForThisPc());
                foreach (var tip in tips)
                {
                    var text = new StackPanel();
                    text.Children.Add(new TextBlock { Text = tip.Name, Style = (Style)FindResource("CardTitle") });
                    text.Children.Add(new TextBlock { Text = tip.Text, Style = (Style)FindResource("Caption"), Margin = new Thickness(0, 2, 0, 0) });
                    GraphicsTipsList.Children.Add(new Border { Style = (Style)FindResource("Card"), Margin = new Thickness(0, 0, 0, 8), Child = text });
                }
                GraphicsTipsPanel.Visibility = tips.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception) { /* the tips are optional, so the page works without them */ }
        }

        private void RestartElevated_Click(object sender, RoutedEventArgs e)
        {
            options.IncludeIdentifiers = Identifiers.IsChecked == true;
            if (Program.RelaunchElevated(options)) Close();
        }

        private async void Run_Click(object sender, RoutedEventArgs e)
        {
            options.IncludeIdentifiers = Identifiers.IsChecked == true;
            scanStarted = true;
            RunButton.IsEnabled = false;
            UpdateButton.IsEnabled = false;
            Identifiers.IsEnabled = false;
            ResultsPanel.Visibility = Visibility.Collapsed;
            ProgressPanel.Visibility = Visibility.Visible;
            Progress.Value = 0;

            Action<int, string> report = (percent, step) => Dispatcher.BeginInvoke((Action)(() =>
            {
                Progress.Value = percent;
                StatusText.Text = step + "...";
            }));

            try
            {
                ShowResult(await Task.Run(() => Scanner.Run(options, report)));
            }
            catch (Exception ex)
            {
                StatusText.Text = "The report couldn't be saved: " + ex.Message;
            }
            RunButton.Content = "Run again";
            RunButton.IsEnabled = true;
            UpdateButton.IsEnabled = true;
            Identifiers.IsEnabled = true;
        }

        public void ShowResult(ScanResult scan)
        {
            result = scan;
            var findings = scan.Report.Findings;
            Progress.Value = 100;
            ProgressPanel.Visibility = Visibility.Visible;
            StatusText.Text = "Saved to " + scan.HtmlPath;
            CriticalCount.Text = findings.Count(f => f.Severity == Severity.Critical).ToString();
            WarningCount.Text = findings.Count(f => f.Severity == Severity.Warning).ToString();
            InfoCount.Text = findings.Count(f => f.Severity == Severity.Info).ToString();
            ScanKind.Text = scan.Report.Elevated ? "Full" : "Limited";

            FindingsList.Children.Clear();
            foreach (var finding in findings) FindingsList.Children.Add(BuildFinding(finding));

            GlanceGrid.Children.Clear();
            GlanceGrid.RowDefinitions.Clear();
            foreach (var fact in scan.Report.Summary)
            {
                int row = GlanceGrid.RowDefinitions.Count;
                GlanceGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                AddToGrid(GlanceGrid, new TextBlock { Text = fact.Name, Style = (Style)FindResource("Secondary"), Margin = new Thickness(0, 2, 12, 2) }, row, 0);
                AddToGrid(GlanceGrid, new TextBlock { Text = fact.Value, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 2) }, row, 1);
            }
            ResultsPanel.Visibility = Visibility.Visible;
        }

        private static void AddToGrid(Grid grid, UIElement element, int row, int column)
        {
            Grid.SetRow(element, row);
            Grid.SetColumn(element, column);
            grid.Children.Add(element);
        }

        private Border BuildFinding(Finding finding)
        {
            string glyph, brush;
            switch (finding.Severity)
            {
                case Severity.Critical: glyph = ""; brush = "CriticalText"; break;
                case Severity.Warning: glyph = ""; brush = "WarningText"; break;
                case Severity.Good: glyph = ""; brush = "Accent"; break;
                default: glyph = ""; brush = "InfoText"; break;
            }

            var text = new StackPanel();
            text.Children.Add(new TextBlock { Text = finding.Title, Style = (Style)FindResource("CardTitle") });
            if (!string.IsNullOrEmpty(finding.Detail))
                text.Children.Add(new TextBlock { Text = finding.Detail, Style = (Style)FindResource("Secondary"), Margin = new Thickness(0, 3, 0, 0) });
            if (!string.IsNullOrEmpty(finding.Advice))
                text.Children.Add(new TextBlock { Text = "Try: " + finding.Advice, Style = (Style)FindResource("Caption"), Margin = new Thickness(0, 6, 0, 0) });

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(32) });
            grid.ColumnDefinitions.Add(new ColumnDefinition());
            AddToGrid(grid, new TextBlock { Text = glyph, Style = (Style)FindResource("Icon"), Foreground = (Brush)FindResource(brush), Margin = new Thickness(0, 2, 0, 0) }, 0, 0);
            AddToGrid(grid, text, 0, 1);
            return new Border { Style = (Style)FindResource("Card"), Margin = new Thickness(0, 0, 0, 8), Child = grid };
        }

        private Button BuildCommandButton(Fix fix, bool undo, string label, TextBlock status)
        {
            var button = new Button { Content = label, MinWidth = 72, Margin = new Thickness(8, 0, 0, 0) };
            button.Click += async (s, e) =>
            {
                if (fix.Caution != null && !await Ask(fix.Name, fix.Caution, label)) return;
                // Read before the command runs, or Undo would return to the changed setting.
                var previous = undo ? null : Fixes.CaptureState(fix);
                bool started = Fixes.Run(undo ? Fixes.UndoCommand(fix) : fix.Command);
                if (started && undo) Fixes.ForgetState(fix);
                else if (started) Fixes.RememberState(fix, previous);
                status.Text = started
                    ? "Started: " + fix.Name + ". Read the result in its window, then close it."
                    : "Not started, because the Windows permission prompt was declined.";
            };
            return button;
        }

        private Border BuildFixRow(Fix fix, TextBlock status, string runLabel)
        {
            var text = new StackPanel { Margin = new Thickness(0, 0, 16, 0) };
            text.Children.Add(new TextBlock { Text = fix.Name, Style = (Style)FindResource("CardTitle") });
            text.Children.Add(new TextBlock { Text = fix.When, Style = (Style)FindResource("Caption"), Margin = new Thickness(0, 2, 0, 0) });
            if (fix.Status != null)
            {
                var line = new TextBlock { Text = "Checking...", Style = (Style)FindResource("Caption"), Foreground = (Brush)FindResource("Accent"), Margin = new Thickness(0, 4, 0, 0) };
                text.Children.Add(line);
                statusLines.Add(new System.Collections.Generic.KeyValuePair<Fix, TextBlock>(fix, line));
            }

            var buttons = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            if (fix.Undo != null) buttons.Children.Add(BuildCommandButton(fix, true, "Undo", status));
            buttons.Children.Add(BuildCommandButton(fix, false, runLabel, status));

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition());
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            AddToGrid(grid, text, 0, 0);
            AddToGrid(grid, buttons, 0, 1);
            return new Border { Style = (Style)FindResource("Card"), Margin = new Thickness(0, 0, 0, 8), Child = grid };
        }

        private Task<bool> Ask(string title, string text, string confirm)
        {
            DialogTitle.Text = title;
            DialogText.Text = text;
            DialogYes.Content = confirm;
            DialogLayer.Visibility = Visibility.Visible;
            question = new TaskCompletionSource<bool>();
            return question.Task;
        }

        private void Answer(bool yes)
        {
            DialogLayer.Visibility = Visibility.Collapsed;
            question.TrySetResult(yes);
        }

        private void DialogYes_Click(object sender, RoutedEventArgs e) { Answer(true); }
        private void DialogNo_Click(object sender, RoutedEventArgs e) { Answer(false); }

        // Going through Explorer opens the browser as the normal user, not as administrator.
        private static void OpenUnelevated(string target) { Process.Start("explorer.exe", "\"" + target + "\""); }

        private void OpenReport_Click(object sender, RoutedEventArgs e) { OpenUnelevated(result.HtmlPath); }
        private void ShowFile_Click(object sender, RoutedEventArgs e) { Process.Start("explorer.exe", "/select,\"" + result.HtmlPath + "\""); }
        private void Repository_Click(object sender, RoutedEventArgs e) { OpenUnelevated("https://github.com/" + Updater.Repository); }

        private void UpdateSettings_Click(object sender, RoutedEventArgs e)
        {
            bool auto = AutoUpdate.IsChecked == true;
            if (auto) NotifyOnLaunch.IsChecked = true; // installing at launch means checking at launch
            NotifyOnLaunch.IsEnabled = !auto;
            try
            {
                UpdateSettings.AutoUpdate = auto;
                UpdateSettings.NotifyOnLaunch = NotifyOnLaunch.IsChecked == true;
            }
            catch (Exception ex)
            {
                UpdateStatus.Text = "Couldn't save the update setting: " + ex.Message;
            }
        }

        // Runs once when the window opens, only if the user turned on a launch check. A failed check stays quiet.
        private async Task CheckAtLaunch()
        {
            bool notify = UpdateSettings.NotifyOnLaunch, auto = UpdateSettings.AutoUpdate;
            if (!notify && !auto) return;
            bool inPlace = Updater.CanInstallInPlace();
            UpdateInfo info;
            try { info = await Task.Run(() => Updater.Check(Updater.CurrentVersion())); }
            catch (Exception) { return; }

            var action = UpdatePlan.Decide(notify, auto, info, inPlace);
            if (action == LaunchAction.Nothing) return;
            launchUpdate = info;
            if (action == LaunchAction.Notify)
            {
                ShowUpdateBar("Feverfew " + info.Latest + " is available", "You have " + info.Current + ".", "Update");
                return;
            }

            ShowUpdateBar("Updating Feverfew to " + info.Latest, "Downloading it and checking the publisher's signature...", null);
            UpdateButton.IsEnabled = false;
            try
            {
                verifiedSetup = await Task.Run(() => Updater.Download(info));
            }
            catch (UpdateRefusedException ex)
            {
                ShowUpdateBar("Feverfew " + info.Latest + " wasn't installed", ex.Message, "Open release page");
                UpdateBarButton.Tag = ex.PageUrl;
                return;
            }
            catch (Exception ex)
            {
                ShowUpdateBar("Feverfew " + info.Latest + " is available", "The automatic download failed: " + ex.Message, "Update");
                return;
            }
            finally
            {
                if (RunButton.IsEnabled) UpdateButton.IsEnabled = true;
            }

            // Don't close the window under a scan the user started while the download ran.
            if (scanStarted)
            {
                ShowUpdateBar("Feverfew " + info.Latest + " is ready to install", "It's downloaded and signed by the publisher. Feverfew will close, update and reopen.", "Install now");
                return;
            }
            InstallSilently();
        }

        private void ShowUpdateBar(string title, string text, string button)
        {
            UpdateBarTitle.Text = title;
            UpdateBarText.Text = text;
            UpdateBarButton.Content = button;
            UpdateBarButton.Tag = null;
            UpdateBarButton.Visibility = button == null ? Visibility.Collapsed : Visibility.Visible;
            UpdateBar.Visibility = Visibility.Visible;
        }

        // The installer reopens Feverfew when it's done (the relaunch entry in installer\setup.iss).
        private void InstallSilently()
        {
            Process.Start(new ProcessStartInfo(verifiedSetup, UpdatePlan.SilentArguments) { UseShellExecute = true });
            Close();
        }

        private async void UpdateBar_Click(object sender, RoutedEventArgs e)
        {
            var page = UpdateBarButton.Tag as string;
            if (page != null) { OpenUnelevated(page); return; }
            if (!RunButton.IsEnabled) { UpdateBarText.Text = "Wait for the scan to finish, then update."; return; }
            if (verifiedSetup != null)
            {
                InstallSilently();
                return;
            }
            UpdateBar.Visibility = Visibility.Collapsed;
            NavUpdates.IsChecked = true;
            await RunUpdate(launchUpdate);
        }

        private async void CheckUpdates_Click(object sender, RoutedEventArgs e) { await RunUpdate(null); }

        /// <summary>The interactive update: asks first, then downloads, verifies and opens the installer's wizard.</summary>
        private async Task RunUpdate(UpdateInfo known)
        {
            RunButton.IsEnabled = false;
            UpdateButton.IsEnabled = false;
            UpdateStatus.Text = "Asking GitHub for the latest version...";
            try
            {
                var current = Updater.CurrentVersion();
                var info = known ?? await Task.Run(() => Updater.Check(current));
                if (!info.IsNewer)
                {
                    UpdateStatus.Text = "You have the latest version.";
                    return;
                }

                bool install = info.CanDownload && Updater.CanInstallInPlace();
                var message = "Feverfew " + info.Latest + " is available. You have " + current + ".";
                if (!await Ask("Update available", message, install ? "Download and install" : "Open download page"))
                {
                    UpdateStatus.Text = "Update skipped.";
                    return;
                }

                if (!install)
                {
                    OpenUnelevated(info.PageUrl);
                    UpdateStatus.Text = "The download page is open in your browser.";
                    return;
                }

                UpdateStatus.Text = "Downloading the update...";
                var setup = await Task.Run(() => Updater.Download(info));
                Process.Start(new ProcessStartInfo(setup) { UseShellExecute = true });
                Close();
            }
            catch (UpdateRefusedException ex)
            {
                UpdateStatus.Text = "Update not installed: " + ex.Message;
                if (await Ask("Update not installed", ex.Message + "\n\nYou can check the release yourself on its GitHub page:\n" + ex.PageUrl, "Open release page"))
                    OpenUnelevated(ex.PageUrl);
            }
            catch (Exception ex)
            {
                UpdateStatus.Text = "Couldn't check for updates: " + ex.Message;
            }
            finally
            {
                RunButton.IsEnabled = true;
                UpdateButton.IsEnabled = true;
            }
        }
    }
}
