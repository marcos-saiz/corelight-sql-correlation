# Examples

End-to-end walkthroughs of the pipeline on sample data.

## Available examples

| Example | What it shows |
|---|---|
| [`01_known_devices_only.md`](01_known_devices_only.md) | Vendor-only enrichment with just `known_devices.log` — the simplest case, useful for showing the pipeline works |
| [`02_with_software_log.md`](02_with_software_log.md) | Product + version enrichment with `software.log` (and equivalents) — where the real value lives |

## Reading order

Start with Example 1 to see the pipeline running end to end on the sample known_devices record (it's the actual record in `data/samples/`). Then move to Example 2 to understand how the pattern scales when richer logs are available.

Example 1 is runnable right now against the sample data. Example 2 is a walkthrough because it requires `software.log` records that you'll need to source from your own environment.
