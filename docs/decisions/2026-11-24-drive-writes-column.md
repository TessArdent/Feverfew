# Lifetime writes next to wear in "Physical drives" (DI-14)

**Decision.** "Physical drives" has a Written column, such as "30 TB (about 26.8 GB per power-on hour)". `DriveWrites.HeavyWriting` raises an Info finding when all of these hold:
- at least 100 power-on hours;
- wear of at least 3%;
- a wear pace of at least 2% per 1,000 power-on hours, which would use the rated life in under 50,000 power-on hours;
- an average of at least 10 GB per power-on hour (240 GB per power-on day).

**Why these thresholds.**
- Everyday desktop use writes a few GB per power-on hour or less. Heavy gaming with frequent large updates rarely averages above about 5 GB/h over a drive's life.
- 10 GB/h is about twice that. It catches background writers such as the AMD atieclxx bug (about 2.3 GB/h on its own, more with real churn), runaway logs, torrenting to the system drive, and a previous owner's workload, without flagging ordinary users.
- The user report that prompted this (a Kingston NV3 2 TB at 5% wear after 1,120 hours, about 30 TB written) is at about 27 GB/h and 4.5% per 1,000 h, so it is flagged.
- The wear conditions keep the finding to drives where the writing has actually cost life. The hour and wear minimums keep noise from a new drive's first days out.
- At 90% wear, the existing "near the end of its rated life" Warning takes over, so this one is skipped.

**Units.** Decimal (1 TB = 10^12 bytes), the way TBW endurance ratings are published, so the two can be compared directly. Other sizes in the report use `Fmt.Bytes` (binary), and the section note says Written is decimal.

**Source.** The NVMe health log's Data Units Written, units of 512,000 bytes, read by `NvmeHealth.Read`. A value of 0 counts as not reported.
- SATA SSDs keep host writes in a vendor SMART attribute (usually 241, Total LBAs Written). Windows' `MSFT_StorageReliabilityCounter` doesn't expose it, so SATA shows a dash.
- Reading it needs ATA pass-through and per-vendor units. That is a separate card.
