# Space Storage Forensics — TraceDiff

This repository contains **TraceDiff v1.0.0** and flight telemetry accompanying *SpaceDrives: An Exploratory Forensic Analysis of Stratosphere-Exposed Storage Devices*.

TraceDiff compares two corresponding, equal-length raw acquisitions of the same storage device. It calculates whole-image MD5, SHA-1, and SHA-256 hashes; localizes sector, byte, and bit differences; optionally maps changed locations to NTFS or FAT filesystem objects; and compares selected file streams byte-for-byte.

The tool can compare acquisitions separated by a flight or another event. It reports differences and structural context; it does not establish the cause or timing of a change.

## Repository contents

| Location | Contents |
| --- | --- |
| [`scripts/tracediff.py`](scripts/tracediff.py) | Command-line tool and guided terminal interface |
| [`flight_data/`](flight_data/) | Flight telemetry workbook for the balloon case study |

The flight workbook, `Flight Analysis2025-06-13 VT to NH.xlsx`, contains three worksheets: `Flight Analysis 2025-06-13 VT t`, `Bounder 5 Raw`, and `Bounder 1 Raw`. Consult the workbook's column headings and annotations when interpreting its measurements.

**Raw storage images are not included in this repository.** Users must provide their own corresponding acquisitions. The flight workbook is contextual data, not an input to TraceDiff. Downloading this repository alone does not provide the images needed to repeat the study's storage comparisons.

## Requirements

- **Python 3.10 or later.** TraceDiff uses the standard library; no additional pip packages are required.
- **Two corresponding raw images** of the same device and acquisition scope, with equal lengths: a baseline image and a comparison image.
- **The Sleuth Kit 4.x** for optional filesystem mapping and stream extraction. Core image comparison does not require it.
- Read access to both images and sufficient writable space for reports and temporary extracted streams.

Download [Python](https://www.python.org/downloads/) and [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/download.php) from their official websites. On Windows, extract the Sleuth Kit binaries and locate the folder containing its executables. Supply that folder through the guided menu or `--tsk-bin`, or place the executables on `PATH`.

Filesystem and stream modes check for `fsstat`, `ifind`, `istat`, and `icat`. The guided partition selector also uses `mmls`; filename search uses `fls`. Install the complete Sleuth Kit distribution to use these conveniences.

## Prepare the input images

TraceDiff does not read E01/Ex01 containers directly. Export acquisitions to raw (`dd`) format before comparison, for example using FTK Imager's raw export function. Supply each acquisition as one complete raw file.

Verify device correspondence, acquisition scope, and logical sector size. Equal file sizes alone do not establish correspondence. Keep inputs stable throughout analysis. TraceDiff opens image files for reading; it does not acquire devices, wipe media, or enforce write protection on physical devices.

## Quick start: guided menu

Open a terminal in the repository's `scripts` folder and run:

```sh
python tracediff.py
```

If your system invokes Python 3 as `python3`, substitute that command. On Windows, `py -3` can also be used when available.

| Option | Function |
| --- | --- |
| 1 | Compare image hashes and sector, byte, and bit differences |
| 2 | Add filesystem mapping |
| 3 | Add filesystem mapping and selected file-stream comparison |
| 4 | Check the local setup |
| 5 | Show the built-in instructions |
| 6 | Exit |

Select the baseline image first and the comparison image second. Place images in `scripts/images/`, which the tool creates when selecting images or checking setup, or enter their full paths.

For options 2 and 3, select the volume's starting sector. Option 3 can search filenames in both images or accept an existing JSON stream manifest.

The guided menu uses **512-byte logical sectors** and an **8 MiB comparison buffer**. Use the command-line interface for another logical sector size. Verify partition discovery independently: failure to detect a partition table does not prove that the filesystem starts at sector zero.

By default, results are written to:

```text
scripts/results/<before-filename>_vs_<after-filename>_<date-time>/
```

Open `report.txt` first. The menu prints a command for repeating the run and copies any selected stream manifest to `streams-manifest.json` in the results folder.

## Command-line usage

The examples below assume the terminal is in `scripts/`. Replace image paths, partition offsets, and executable paths with verified values. Quote paths containing spaces. Each custom output directory must be new; existing output directories are not overwritten.

### Basic image comparison

```sh
python tracediff.py compare "baseline.raw" "comparison.raw" --output "results/basic_run"
```

### Filesystem mapping

```sh
python tracediff.py compare "baseline.raw" "comparison.raw" --filesystem --partition-offset 32768 --tsk-bin "/path/to/tsk/bin" --output "results/mapping_run"
```

**The offset `32768` is an example, not a default.** Determine the correct offset from acquisition records and partition inspection, such as `mmls`, and verify the selected volume in both images. Use `0` only when the selected filesystem begins at the start of the image. The tool applies the same specified offset to both inputs.

### Mapping and selected stream comparison

```sh
python tracediff.py compare "baseline.raw" "comparison.raw" --filesystem --partition-offset 32768 --tsk-bin "/path/to/tsk/bin" --streams "streams.json" --output "results/stream_run"
```

Stream comparison can also be requested without `--filesystem`. The `--streams` option still requires The Sleuth Kit and an explicit partition offset.

### Other logical sector sizes

```sh
python tracediff.py compare "baseline.raw" "comparison.raw" --sector-size 4096 --output "results/4096_run"
```

Use the acquisition's actual logical sector size. For 512e media presenting 512-byte logical sectors, use `512`, even though physical sectors are larger.

### Help and version

```sh
python tracediff.py --version
python tracediff.py compare --help
```

### Stream manifest

Create a UTF-8 JSON file containing a list of corresponding stream identifiers:

```json
[
  {
    "label": "photo.jpg",
    "before_id": "43-128-1",
    "after_id": "43-128-1"
  }
]
```

These identifiers are examples. Obtain and verify the appropriate Sleuth Kit extraction identifiers independently in each image; they may differ between acquisitions. The label describes the comparison and is not used to locate or verify a file.

The guided filename search selects allocated regular files found under matching paths in both images and excludes alternate data streams. A manually supplied manifest can specify other valid extraction identifiers. The examiner remains responsible for establishing correspondence between selected streams.

Preserve the manifest for repeat runs. Command-line mode does not automatically copy it into the results folder.

### Options

| Option | Meaning and default |
| --- | --- |
| `--output` | New results directory; otherwise an automatically named folder under `scripts/results/` |
| `--sector-size` | Logical sector size in bytes; default `512` |
| `--buffer-mib` | Buffered comparison read size in MiB; default `8` |
| `--filesystem` | Enable NTFS/FAT mapping of changed data units |
| `--partition-offset` | Selected volume start in logical sectors; explicitly required for filesystem or stream analysis |
| `--tsk-bin` | Folder containing Sleuth Kit executables; otherwise use `PATH` |
| `--streams` | JSON manifest for selected stream comparison |

## Outputs

| File or folder | Contents |
| --- | --- |
| `report.txt` | Readable summary, hashes, difference counts, and previews of detailed results |
| `summary.json` | Machine-readable run status, input paths, hashes, counts, and optional stream results |
| `sectors.csv` | Differing sector LBAs and per-sector byte and bit counts |
| `ranges.csv` | Contiguous differing-sector ranges with inclusive start and end LBAs |
| `bytes.csv` | Exact offsets, before/after byte values, XOR values, and differing bit positions |
| `filesystem.csv` | Optional per-image filesystem associations and mapping statuses |
| `streams.json` | Optional selected-stream sizes, SHA-256 hashes, and byte-comparison outcomes |
| `tsk/` | Sleuth Kit text outputs, error outputs, and `commands.json` recording arguments and return codes |
| `streams-manifest.json` | Manifest copy saved by guided runs when streams are selected |

Temporary extracted stream files are removed after comparison. Stream results are JSON, not a separate CSV. The text report contains limited previews; use the detailed files for complete records. Large numbers of changed bytes can produce large CSV files.

## Interpretation and limitations

- Offsets and LBAs are zero-based. Bit position `0` is the least significant bit.
- A differing sector contains at least one differing byte; the entire sector need not differ.
- `byte_identical` is determined by direct comparison, independently of hash matching.
- NTFS mapping converts image-relative sectors to partition-relative clusters. FAT mapping uses partition-relative sectors. Associations are examined separately in each image.
- Automatic filesystem mapping supports NTFS and FAT. Other filesystems can still undergo raw comparison.
- A filesystem association provides structural context. It does not automatically identify the changed metadata field or explain its cause. Inspect supporting records and logs before interpreting associations.
- The mapper explicitly marks sectors before the selected partition. It does not comprehensively validate changed locations against the selected volume's end boundary.
- Identical selected streams establish preservation only of those extracted contents. They do not establish preservation of all files, metadata, alternate streams, or unallocated space.
- Check the overall run status and errors before using results. Optional analysis may fail after raw comparison completes, leaving partial outputs.

## Reproducibility

Retain the input images and their hashes, TraceDiff version, Python and Sleuth Kit versions, logical sector size, partition offset, stream manifest, exact command, and complete output folder.

Command logs support inspection and repeatability. They do not independently establish chain of custody or validate every filesystem interpretation.

## Troubleshooting

| Problem | Action |
| --- | --- |
| Images have different lengths | Verify that complete raw exports cover corresponding acquisition scopes |
| E01/Ex01 input rejected | Export to raw before running TraceDiff |
| Output directory already exists | Choose a new directory |
| Sleuth Kit programs not found | Supply the executable directory with `--tsk-bin` or place the tools on `PATH` |
| `fsstat`, `ifind`, or `icat` fails | Check image format, sector size, partition offset, and extraction identifiers; inspect `tsk/` logs |
| Guided filename search fails | Check that `fls` is available; use a verified manifest if needed |
| Input changes during comparison | Preserve stable inputs and rerun into a new output directory |

Successful comparisons return exit code `0`; handled comparison failures return `2`. Read `report.txt` and `summary.json`, when available, to distinguish complete results from failed runs. Argument validation can fail before a results directory is created.

## Licensing

The original TraceDiff software and its associated documentation are licensed under the [MIT License](LICENSE), copyright (c) 2026 Ruba Alsmadi. Third-party datasets and dependencies retain their respective licenses and copyright notices; the MIT license does not grant rights to those materials. No ownership of third-party materials is claimed.
