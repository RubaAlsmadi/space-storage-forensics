#!/usr/bin/env python3
"""TraceDiff 1.0.0: layered, read-only forensic comparison of two raw storage images.

EASIEST WAY: run   python tracediff.py   with no arguments. A numbered menu guides you
through every step, so you never have to type the full command.

PURPOSE
  When two acquisitions of the same device have different hashes, TraceDiff shows
  where they differ (sector, byte, bit), which filesystem structures are affected, and
  whether selected files are unchanged. It reports locations. It does not identify causes.

WHAT YOU NEED
  1. Python 3.10 or newer: https://www.python.org/downloads/   (no pip packages needed)
  2. The Sleuth Kit 4.x, ONLY for filesystem mapping and file comparison (menu options 2, 3):
       Download: https://www.sleuthkit.org/sleuthkit/download.php
       Windows: download the binaries zip and unzip it. The menu asks for its "bin" folder
       once and remembers it. Linux and macOS: install it with your package manager
       (for example "sudo apt install sleuthkit").
     Menu option 1 (quick comparison) needs nothing else.
  3. Two RAW (dd) images of the same device with exactly the same length:
       Image 1 = BEFORE (baseline), Image 2 = AFTER.
       Save both in the "images" folder inside the tool folder (created on first run), or
       keep them anywhere and type their full paths. E01 files are not supported; in
       FTK Imager use Export Disk Image, type Raw (dd).

RESULTS
  Saved inside the tool folder, in results/<image1>_vs_<image2>_<date-time>/.
  Open report.txt first. The CSV and JSON files hold the complete data.

ADVANCED: COMMAND LINE (same functions, no menu)
  python tracediff.py compare "IMAGE_1" "IMAGE_2"
  python tracediff.py compare "IMAGE_1" "IMAGE_2" --filesystem --partition-offset START_SECTOR --tsk-bin "TSK_BIN_FOLDER"
  Add --streams streams.json to compare selected files byte for byte:
    [{"label": "photo.jpg", "before_id": "43-128-1", "after_id": "43-128-1"}]
  START_SECTOR is where the partition begins ("mmls IMAGE_1" shows it; 0 for most USB drives).
  Add --output "FOLDER" to choose another results folder (it must not exist).

Offsets and LBAs are zero-based. Input images are only ever opened for reading.
"""
import argparse
import csv
import hashlib
import json
import os
from itertools import islice
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

VERSION = '1.0.0'
TOOL_DIR = Path(__file__).resolve().parent
TSK_TOOLS = ('fsstat', 'ifind', 'istat', 'icat')
TSK_HELP = ('The Sleuth Kit programs {missing} were not found.\n'
            'Download The Sleuth Kit 4.x from https://www.sleuthkit.org/sleuthkit/download.php , unzip it,\n'
            'then pass its "bin" folder with --tsk-bin "FOLDER" (or add that folder to PATH).\n'
            'The plain comparison does not need it: run again without --filesystem and --streams.')


def _exe(folder, name):
    """Full path of a Sleuth Kit program in `folder`, or on PATH when folder is empty."""
    if folder:
        for suffix in ('', '.exe'):
            p = Path(folder) / (name + suffix)
            if p.is_file(): return str(p.resolve())
        raise ValueError(f'{name} not found in {folder}')
    p = shutil.which(name)
    if not p: raise ValueError(f'{name} not found. Set --tsk-bin.')
    return p


def default_output(before, after):
    """results/<image1>_vs_<image2>_<date-time> inside the tool folder."""
    clean = lambda p: re.sub(r'[^\w.-]', '_', Path(p).name)
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    return TOOL_DIR / 'results' / f'{clean(before)}_vs_{clean(after)}_{stamp}'


def missing_tsk(folder):
    """Return the names of required Sleuth Kit programs that cannot be found."""
    missing = []
    for name in TSK_TOOLS:
        if folder:
            found = any((Path(folder) / (name + s)).is_file() for s in ('', '.exe'))
        else:
            found = shutil.which(name) is not None
        if not found:
            missing.append(name)
    return missing


def compare(before, after, output, sector=512, buffer=8*1024*1024, progress=False):
    before, after, output = Path(before), Path(after), Path(output)
    if sector <= 0 or buffer < sector:
        raise ValueError('Sector size must be positive; buffer must be at least one sector.')
    if before.stat().st_size != after.stat().st_size:
        raise ValueError('Images have different sizes. Full aligned comparison requires equal-length images.')
    if before.suffix.lower() in ('.e01', '.ex01') or after.suffix.lower() in ('.e01', '.ex01'):
        raise ValueError('Use exported raw images, not E01/Ex01 containers.')
    output.mkdir(parents=True, exist_ok=False)
    size = before.stat().st_size
    original = [(p.stat().st_size, p.stat().st_mtime_ns) for p in (before, after)]
    hashes = [{n: hashlib.new(n) for n in ('md5', 'sha1', 'sha256')} for _ in range(2)]
    counts = dict(differing_sectors=0, differing_bytes=0, differing_bits=0, contiguous_ranges=0)
    buffer = buffer // sector * sector
    run = None
    started = time.monotonic()
    last_shown = 0.0
    with before.open('rb') as a, after.open('rb') as b, \
         (output/'sectors.csv').open('w', newline='', encoding='utf-8') as sf, \
         (output/'bytes.csv').open('w', newline='', encoding='utf-8') as bf, \
         (output/'ranges.csv').open('w', newline='', encoding='utf-8') as rf:
        sw, bw, rw = csv.writer(sf), csv.writer(bf), csv.writer(rf)
        sw.writerow(['lba','bytes_compared','differing_bytes','differing_bits','first_sector_offset','last_sector_offset'])
        bw.writerow(['absolute_offset','absolute_offset_hex','lba','sector_offset','before_hex','after_hex','xor_hex','differing_bits','bit_positions_lsb0'])
        rw.writerow(['start_lba','end_lba','sector_count'])
        offset = 0
        while True:
            x, y = a.read(buffer), b.read(buffer)
            if len(x) != len(y):
                raise ValueError('Image length changed during comparison.')
            if not x:
                break
            for h, data in zip(hashes, (x,y)):
                for digest in h.values(): digest.update(data)
            if x != y:
                for i in range(0, len(x), sector):
                    sa, sb = x[i:i+sector], y[i:i+sector]
                    if sa == sb: continue
                    lba = (offset+i)//sector
                    nb = bits = 0
                    first = last = None
                    for j,(u,v) in enumerate(zip(sa,sb)):
                        if u == v: continue
                        xor = u^v
                        nbits = xor.bit_count()
                        nb += 1; bits += nbits
                        first = j if first is None else first; last=j
                        absolute = offset+i+j
                        bw.writerow([absolute,f'0x{absolute:08X}',lba,j,f'0x{u:02X}',f'0x{v:02X}',f'0x{xor:02X}',nbits,';'.join(str(k) for k in range(8) if xor & (1<<k))])
                    sw.writerow([lba,len(sa),nb,bits,first,last])
                    counts['differing_sectors'] += 1
                    counts['differing_bytes'] += nb
                    counts['differing_bits'] += bits
                    if run is not None and lba == run[1]+1:
                        run[1] = lba
                    else:
                        if run is not None:
                            rw.writerow([*run,run[1]-run[0]+1]); counts['contiguous_ranges'] += 1
                        run=[lba,lba]
            offset += len(x)
            if progress:
                now = time.monotonic()
                if now - last_shown >= 1.0:
                    last_shown = now
                    pct = 100 * offset / size if size else 100
                    print(f'\r  comparing: {pct:5.1f}%  ({offset/2**30:,.1f} of {size/2**30:,.1f} GiB, '
                          f'{int(now-started)} s)', end='', file=sys.stderr, flush=True)
        if run is not None:
            rw.writerow([*run,run[1]-run[0]+1]); counts['contiguous_ranges'] += 1
    if progress:
        print(f'\r  comparing: 100.0%  ({size/2**30:,.1f} GiB, {int(time.monotonic()-started)} s)          ', file=sys.stderr)
    if offset != size or original != [(p.stat().st_size,p.stat().st_mtime_ns) for p in (before,after)]:
        raise ValueError('Input changed during comparison; results are incomplete.')
    return dict(tool='TraceDiff',version=VERSION,created_utc=datetime.now(timezone.utc).isoformat(),
                before=str(before.resolve()),after=str(after.resolve()),bytes_compared=size,
                sector_size=sector,sectors_compared=(size+sector-1)//sector,
                final_partial_sector_bytes=size%sector,complete=True,
                byte_identical=counts['differing_bytes']==0,
                hashes={key:{n:h.hexdigest() for n,h in digests.items()} for key,digests in zip(('before','after'),hashes)},
                **counts)


class TSK:
    def __init__(self, folder, output, sector, offset):
        self.folder=Path(folder) if folder else None
        self.output=Path(output); self.sector=sector; self.offset=offset; self.commands=[]
        self.output.mkdir(parents=True,exist_ok=True)
    def executable(self,name):
        return _exe(self.folder,name)
    def args(self,name,image,extra=()):
        return [self.executable(name),'-i','raw','-b',str(self.sector),'-o',str(self.offset),*extra,str(image)]
    def text(self,name,image,extra=(),tail=()):
        cmd=self.args(name,image,extra)+list(tail)
        result=subprocess.run(cmd,capture_output=True,text=True,errors='replace',timeout=120)
        index=len(self.commands)
        (self.output/f'{index:06d}-{name}.txt').write_text(result.stdout,encoding='utf-8')
        (self.output/f'{index:06d}-{name}.stderr.txt').write_text(result.stderr,encoding='utf-8')
        self.commands.append(dict(argv=cmd,returncode=result.returncode))
        if result.returncode: raise ValueError(f'{name} failed; inspect TSK logs.')
        return result.stdout
    def extract(self,image,identifier,destination):
        if not re.fullmatch(r'\d+(?:-\d+-\d+)?',identifier):
            raise ValueError('Stream identifiers must be numeric TSK identifiers.')
        cmd=self.args('icat',image)+[identifier]
        index=len(self.commands)
        with open(destination,'wb') as target, (self.output/f'{index:06d}-icat.stderr.txt').open('wb') as err:
            result=subprocess.run(cmd,stdout=target,stderr=err)
        self.commands.append(dict(argv=cmd,returncode=result.returncode))
        if result.returncode: raise ValueError('icat extraction failed; stream comparison was not performed.')
    def save(self):
        (self.output/'commands.json').write_text(json.dumps(self.commands,indent=2),encoding='utf-8')


def filesystem(tsk,images,output):
    """Map changed units separately in both images; no inferred semantic changes."""
    output=Path(output)
    with (output/'filesystem.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f); w.writerow(['image','lba','filesystem_type','data_unit','unit_kind','ifind_identifiers','status'])
        for phase,image in zip(('before','after'),images):
            info=tsk.text('fsstat',image)
            match=re.search(r'File System Type:\s*(\S+)',info)
            kind=match.group(1).upper() if match else ''
            if kind == 'NTFS':
                match=re.search(r'Cluster Size:\s*(\d+)',info)
                if not match: raise ValueError('Could not determine NTFS cluster size.')
                unit=int(match.group(1))
                if unit < tsk.sector or unit%tsk.sector: raise ValueError('Unsupported NTFS cluster geometry.')
                scale=unit//tsk.sector; unit_kind='cluster'
            elif kind.startswith('FAT'):
                # TSK FAT data units are volume-relative sectors, not FAT cluster numbers.
                scale=1;unit_kind='volume_sector'
            else:
                raise ValueError(f'Automatic filesystem mapping currently supports NTFS and FAT only; got {kind}.')
            cache={}
            with (output/'sectors.csv').open(encoding='utf-8') as sectors:
                for row in csv.DictReader(sectors):
                    lba=int(row['lba'])
                    if lba < tsk.offset:
                        w.writerow([phase,lba,kind,'',unit_kind,'','before_selected_partition']); continue
                    number=(lba-tsk.offset)//scale
                    if number not in cache:
                        found=tsk.text('ifind',image,['-a','-d',str(number)])
                        ids=re.findall(r'^\s*(\d+(?:-\d+-\d+)?)\s*$',found,re.M)
                        for ident in ids: tsk.text('istat',image,tail=[ident])
                        cache[number]=ids
                    ids=cache[number]
                    w.writerow([phase,lba,kind,number,unit_kind,';'.join(ids),'associated' if ids else 'unresolved'])


def stream_compare(tsk,images,manifest,output):
    pairs=json.loads(Path(manifest).read_text(encoding='utf-8'))
    if not isinstance(pairs,list): raise ValueError('Stream manifest must be a JSON list.')
    results=[]
    with tempfile.TemporaryDirectory(prefix='streams-',dir=output) as temporary:
        for pair in pairs:
            pre=Path(temporary)/'before.bin'; post=Path(temporary)/'after.bin'
            tsk.extract(images[0],str(pair['before_id']),pre)
            tsk.extract(images[1],str(pair['after_id']),post)
            hashes=[hashlib.sha256(),hashlib.sha256()]; counts=[0,0]; different=0
            with pre.open('rb') as a, post.open('rb') as b:
                while True:
                    x,y=a.read(1024*1024),b.read(1024*1024)
                    if not x and not y: break
                    for i,data in enumerate((x,y)): hashes[i].update(data);counts[i]+=len(data)
                    if x != y:  # fast path: equal chunks add no differences
                        different += sum(u!=v for u,v in zip(x,y))+abs(len(x)-len(y))
            results.append(dict(label=pair.get('label',''),before_id=pair['before_id'],after_id=pair['after_id'],
                                before_bytes=counts[0],after_bytes=counts[1],byte_identical=different==0,
                                differing_byte_positions=different,before_sha256=hashes[0].hexdigest(),after_sha256=hashes[1].hexdigest()))
            pre.unlink();post.unlink()
    Path(output,'streams.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    return results


# ---------- readable report ----------

def _table(headers, data):
    """Plain-text table with aligned columns."""
    data = [[str(c) for c in row] for row in data]
    widths = [max(len(str(c)) for c in col) for col in zip(headers, *data)]
    def line(cells): return '  ' + '  '.join(str(c).ljust(w) for c, w in zip(cells, widths)).rstrip()
    return [line(headers), line(['-' * w for w in widths])] + [line(r) for r in data]


def _head_csv(path, limit):
    """First `limit` rows of a CSV as dicts (empty if the file is missing)."""
    p = Path(path)
    if not p.is_file(): return []
    with p.open(encoding='utf-8', newline='') as f:
        return list(islice(csv.DictReader(f), limit))


def _filesystem_groups(output):
    """Group filesystem.csv by image and identifier without loading it all."""
    groups = {}
    p = Path(output, 'filesystem.csv')
    if not p.is_file(): return groups
    with p.open(encoding='utf-8', newline='') as f:
        for r in csv.DictReader(f):
            key = (r['image'], r['ifind_identifiers'] or r['status'])
            lba = int(r['lba'])
            g = groups.setdefault(key, [0, lba, lba, r['filesystem_type'], r['unit_kind']])
            g[0] += 1; g[1] = min(g[1], lba); g[2] = max(g[2], lba)
    return groups


def report(summary,output):
    Path(output,'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    n = lambda k: f"{summary[k]:,}" if isinstance(summary.get(k), int) and not isinstance(summary.get(k), bool) else str(summary.get(k, 'n/a'))
    L = ['TRACEDIFF COMPARISON REPORT', '=' * 27,
         f"Tool version : {VERSION}", f"Status       : {summary['status']}"]
    if 'created_utc' in summary: L.append(f"Created (UTC): {summary['created_utc']}")
    if 'before' in summary: L += [f"Before image : {summary['before']}", f"After image  : {summary['after']}"]
    if 'error' in summary: L += ['', 'ERROR: ' + summary['error']]

    if summary.get('complete'):
        L += ['', '1. IMAGE-LEVEL RESULT', '-' * 21,
              f"Bytes compared   : {n('bytes_compared')}",
              f"Sector size      : {n('sector_size')} bytes   (sectors compared: {n('sectors_compared')})"]
        if summary.get('final_partial_sector_bytes'):
            L.append(f"Final partial sector: {summary['final_partial_sector_bytes']} bytes (included in the comparison)")
        L.append('Hashes:')
        names = {'md5': 'MD5', 'sha1': 'SHA-1', 'sha256': 'SHA-256'}
        for key, label in names.items():
            hb, ha = summary['hashes']['before'][key], summary['hashes']['after'][key]
            L += [f"  {label:<7} before: {hb}", f"  {'':<7} after : {ha}",
                  f"  {'':<7} match : {'YES' if hb == ha else 'NO'}"]
        L.append('Verdict: ' + ('The images are byte-for-byte identical.' if summary['byte_identical']
                               else 'The images DIFFER. Sections 2 to 4 show where and what.'))

        L += ['', '2. WHERE AND WHAT CHANGED', '-' * 24,
              f"Differing sectors : {n('differing_sectors')}",
              f"Contiguous ranges : {n('contiguous_ranges')}",
              f"Differing bytes   : {n('differing_bytes')}",
              f"Differing bits    : {n('differing_bits')}"]
        ranges = _head_csv(Path(output, 'ranges.csv'), 50)
        if ranges:
            L += ['', 'Differing sector ranges (zero-based LBA, inclusive):']
            L += _table(['start_lba', 'end_lba', 'sectors'], [[r['start_lba'], r['end_lba'], r['sector_count']] for r in ranges])
            if summary.get('contiguous_ranges', 0) > 50:
                L.append(f"  ... first 50 of {summary['contiguous_ranges']:,} shown. See ranges.csv for all.")
        if 0 < summary.get('differing_bytes', 0):
            shown = _head_csv(Path(output, 'bytes.csv'), 20)
            L += ['', 'Changed bytes (bit positions count from 0 = least significant):']
            L += _table(['offset', 'lba', 'in_sector', 'before', 'after', 'xor', 'bits', 'bit_positions'],
                        [[r['absolute_offset_hex'], r['lba'], r['sector_offset'], r['before_hex'], r['after_hex'],
                          r['xor_hex'], r['differing_bits'], r['bit_positions_lsb0']] for r in shown])
            if summary['differing_bytes'] > 20:
                L.append(f"  ... first 20 of {summary['differing_bytes']:,} shown. See bytes.csv for all.")

        L += ['', '3. FILESYSTEM MAPPING', '-' * 21, f"Status: {summary.get('filesystem_status', 'not requested')}"]
        groups = _filesystem_groups(output)
        if groups:
            L.append('Differing sectors grouped by Sleuth Kit identifier. Identifiers should agree between')
            L.append('the before and after images. Read the raw istat files in tsk/ to interpret them.')
            rows = [[img, ident, g[0], f"{g[1]}-{g[2]}" if g[1] != g[2] else g[1], f"{g[3]} ({g[4]})"]
                    for (img, ident), g in sorted(groups.items())]
            L += _table(['image', 'identifier / status', 'sectors', 'lba_span', 'filesystem (unit)'], rows)
            L.append("'unresolved' means TSK found no owner. It is not evidence of corruption or of free space.")
            L.append("'before_selected_partition' means the sector lies outside the selected partition.")

        L += ['', '4. SELECTED FILE STREAMS', '-' * 24]
        if summary.get('stream_results'):
            res = summary['stream_results']
            same = sum(1 for r in res if r['byte_identical'])
            L.append(f"{same} of {len(res)} selected streams are byte-for-byte identical.")
            L += _table(['label', 'before_id', 'after_id', 'before_bytes', 'after_bytes', 'result', 'differing_bytes'],
                        [[r['label'], r['before_id'], r['after_id'], f"{r['before_bytes']:,}", f"{r['after_bytes']:,}",
                          'IDENTICAL' if r['byte_identical'] else 'DIFFERENT', f"{r['differing_byte_positions']:,}"] for r in res])
            L.append('SHA-256 of each extracted stream is in streams.json.')
        else:
            L.append('not requested')

    L += ['', 'SCOPE NOTES', '-' * 11,
          '* Offsets and LBAs are zero-based. Ranges are inclusive.',
          '* Associations locate differences. They do not identify their cause and do not decode metadata fields.',
          '* Stream results apply only to the selected streams. Unexamined content is not verified.',
          '* Hashes show whether the images differ. The exact comparison is what localizes the differences.',
          '* Files: summary.json, sectors.csv, ranges.csv, bytes.csv, filesystem.csv, streams.json, tsk/ (when requested).']
    Path(output,'report.txt').write_text('\n'.join(L)+'\n',encoding='utf-8')


def execute(a):
    """Run one full job. `a` needs: before, after, output, sector_size, buffer_mib,
    filesystem, partition_offset, tsk_bin, streams. Returns an exit code."""
    summary={'tool':'TraceDiff','version':VERSION,'complete':False,'status':'failed'}
    tsk=None
    try:
        summary=compare(a.before,a.after,a.output,a.sector_size,a.buffer_mib*1024*1024,progress=True)
        summary['status']='complete';summary['argv']=sys.argv
        if a.filesystem or a.streams:
            tsk=TSK(a.tsk_bin,a.output/'tsk',a.sector_size,a.partition_offset)
            summary['partition_offset']=a.partition_offset
            summary['tsk_version']=tsk.text('fsstat',a.before,extra=['-V']).strip()
            if a.filesystem:
                summary['filesystem_status']='in progress'
                print('  mapping differing sectors with The Sleuth Kit ...',file=sys.stderr)
                filesystem(tsk,(a.before,a.after),a.output)
                summary['filesystem_status']='completed'
            if a.streams:
                print('  comparing selected streams ...',file=sys.stderr)
                summary['stream_results']=stream_compare(tsk,(a.before,a.after),a.streams,a.output)
                summary['streams_compared']=len(summary['stream_results'])
        report(summary,a.output)
        print(f"Compared {summary['bytes_compared']:,} bytes: {summary['differing_sectors']:,} sectors, {summary['differing_bytes']:,} bytes, {summary['differing_bits']:,} bits differ.")
        print('Verdict: ' + ('images are byte-for-byte identical.' if summary['byte_identical'] else 'images differ. See the report for locations.'))
        print(f'Results saved in: {a.output.resolve()}')
        print(f'Start with:       {(a.output / "report.txt").resolve()}')
        return 0
    except (ValueError,OSError,subprocess.SubprocessError,KeyError,TypeError) as e:
        summary['status']='failed';summary['error']=str(e)
        if summary.get('filesystem_status')=='in progress': summary['filesystem_status']='failed'
        if a.output.exists(): report(summary,a.output)
        print(f'ERROR: {e}',file=sys.stderr);return 2
    finally:
        if tsk: tsk.save()


# ---------- interactive menu ----------

TSK_URL = 'https://www.sleuthkit.org/sleuthkit/download.php'
IMAGES_DIR = TOOL_DIR / 'images'
TSK_MEMORY = TOOL_DIR / 'tsk_path.txt'
NOT_IMAGES = ('.txt', '.md', '.csv', '.json', '.log', '.py', '.pdf')
MMLS_ROW = re.compile(r'^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*\S)\s*$')
FLS_ROW = re.compile(r'^r/r\s+(\*\s+)?(\d+(?:-\d+-\d+)?)(?:\([^)]*\))?:\s+(.*)$')


class GoBack(Exception):
    """Raised when the user types q to return to the main menu."""


def _ask(prompt, back=False):
    try:
        text = input(prompt).strip().strip('"').strip("'").strip()
    except (EOFError, KeyboardInterrupt):
        print(); raise SystemExit(0)
    if back and text.lower() == 'q':
        raise GoBack
    return text


def _title(text):
    print('\n' + '=' * 70 + f'\n {text}\n' + '=' * 70)


def find_tsk():
    """Look for The Sleuth Kit. Returns (found, folder); folder is '' when it is on PATH."""
    candidates = []
    if TSK_MEMORY.is_file():
        candidates.append(TSK_MEMORY.read_text(encoding='utf-8').strip())
    candidates.append('')
    for base in (TOOL_DIR, Path.home() / 'Downloads', Path.home() / 'Desktop'):
        try:
            candidates += [str(hit.parent) for hit in base.glob('sleuthkit*/**/fsstat*')]
        except OSError:
            pass
    for c in candidates:
        if c is not None and not missing_tsk(c or None):
            return True, c
    return False, ''


def ensure_tsk():
    """Make sure The Sleuth Kit is available. Returns (ok, folder)."""
    found, folder = find_tsk()
    if found:
        print('  The Sleuth Kit was found' + (f': {folder}' if folder else ' (on PATH).'))
        return True, folder
    print('  The Sleuth Kit was NOT found, and this option needs it.')
    print(f'    1. Download it from: {TSK_URL}')
    print('    2. Unzip it (on Windows choose the binaries zip).')
    print('    3. Open the unzipped folder and find the "bin" folder (it contains fsstat.exe).')
    while True:
        text = _ask('  Paste the full path of that bin folder, or press Enter to go back: ')
        if not text:
            return False, ''
        missing = missing_tsk(text)
        if missing:
            print(f'  These programs were not found in that folder: {", ".join(missing)}. Check the path.')
            continue
        TSK_MEMORY.write_text(text, encoding='utf-8')
        print('  Saved. You will not be asked for this folder again.')
        return True, text


def _pick_image(label, files):
    while True:
        text = _ask(f'  {label}: number from the list or full path (q = back to menu): ', back=True)
        path = files[int(text) - 1] if text.isdigit() and 1 <= int(text) <= len(files) else Path(text).expanduser()
        if not path.is_file():
            print('  That file was not found. Check the path and try again.'); continue
        if path.suffix.lower() in ('.e01', '.ex01'):
            print('  E01 files are not supported. Export the image to raw (dd) first, for example with'
                  '\n  FTK Imager: Export Disk Image, type Raw (dd).'); continue
        return path


def choose_images():
    """Ask for the two images. Returns (before, after) or None."""
    IMAGES_DIR.mkdir(exist_ok=True)
    files = sorted(f for f in IMAGES_DIR.iterdir()
                   if f.is_file() and f.suffix.lower() not in NOT_IMAGES and not f.name.startswith('.'))
    print('\nSTEP: choose your two images')
    print('  Both must be RAW (dd) images of the SAME device, with exactly the same size.')
    print('  Image 1 is the BEFORE (baseline) image. Image 2 is the AFTER image.')
    print(f'  Save both images in this folder, or type their full paths:\n    {IMAGES_DIR}')
    if files:
        print('  Images found in that folder:')
        for i, f in enumerate(files, 1):
            print(f'    {i}  {f.name}  ({f.stat().st_size:,} bytes)')
    else:
        print('  (That folder is empty. Copy your two images into it, or type full paths.)')
    first = _pick_image('Image 1 (BEFORE)', files)
    second = _pick_image('Image 2 (AFTER) ', files)
    if first.resolve() == second.resolve():
        print('  Image 1 and Image 2 are the same file. Choose two different images.'); return None
    if first.stat().st_size != second.stat().st_size:
        print(f'  The images have different sizes ({first.stat().st_size:,} and {second.stat().st_size:,} bytes).'
              '\n  Both must be acquisitions of the same device. Check the files and try again.'); return None
    return first, second


def choose_partition(folder, image):
    """Ask where the partition starts. Returns the start sector."""
    print('\nSTEP: choose the partition (the volume to analyse)')
    rows = []
    try:
        result = subprocess.run([_exe(folder or None, 'mmls'), str(image)], capture_output=True,
                                text=True, errors='replace', timeout=120)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                m = MMLS_ROW.match(line)
                if m and m.group(2) not in ('Meta', '-------'):
                    rows.append((int(m.group(3)), int(m.group(5)), m.group(6)))
    except (ValueError, OSError, subprocess.SubprocessError):
        pass
    if rows:
        print('  Partitions found in Image 1:')
        for i, (start, length, desc) in enumerate(rows, 1):
            print(f'    {i}  starts at sector {start:,}   {desc}   ({length:,} sectors)')
        print('    0  none of these; I will type the start sector myself')
        while True:
            text = _ask('  Enter the number of the partition to analyse (q = back to menu): ', back=True)
            if text == '0': break
            if text.isdigit() and 1 <= int(text) <= len(rows): return rows[int(text) - 1][0]
            print('  Please enter one of the numbers above.')
    else:
        print('  No partition table was found. This is normal for a USB flash drive whose filesystem')
        print('  starts at the beginning of the image. In that case the start sector is 0.')
    while True:
        text = _ask('  Start sector of the partition [Enter = 0, q = back to menu]: ', back=True)
        if not text: return 0
        if text.isdigit(): return int(text)
        print('  Please enter a whole number.')


def find_files(folder, image, offset, needle, sector=512, limit=100):
    """Regular files whose path contains `needle`. Returns {path: identifier}."""
    cmd = [_exe(folder or None, 'fls'), '-r', '-p', '-i', 'raw', '-b', str(sector), '-o', str(offset), str(image)]
    found, needle = {}, needle.lower()
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors='replace') as proc:
        for line in proc.stdout:
            m = FLS_ROW.match(line.rstrip('\r\n'))
            if not m or m.group(1):
                continue  # not an allocated regular file
            path = m.group(3)
            if ':' in path.rsplit('/', 1)[-1]:
                continue  # alternate data stream
            if needle in path.lower():
                found.setdefault(path, m.group(2))
                if len(found) >= limit:
                    proc.kill(); break
    return found


def choose_streams(folder, before, after, offset):
    """Optional: pick files to compare byte for byte. Returns a manifest path or None."""
    print('\nSTEP: files to compare byte for byte (optional)')
    print('  1  Search for files by name')
    print('  2  I already have a streams.json file')
    print('  Enter  Skip this step')
    mode = _ask('  Your choice (q = back to menu): ', back=True)
    if mode == '2':
        while True:
            text = _ask('  Full path of your streams.json (Enter to skip): ')
            if not text: return None
            if Path(text).is_file(): return Path(text)
            print('  That file was not found.')
    if mode != '1':
        return None
    entries = {}
    while True:
        needle = _ask('  Part of a file name to search for, such as .pdf or report (Enter when finished): ')
        if not needle: break
        print('  Searching both images. This can take a few minutes on large disks ...')
        try:
            b = find_files(folder, before, offset, needle)
            a = find_files(folder, after, offset, needle)
        except (ValueError, OSError) as e:
            print(f'  Search failed: {e}'); break
        both = [path for path in b if path in a]
        if len(b) != len(both) or len(a) != len(both):
            print('  Some matches exist in only one image; they are skipped.')
        if not both:
            print('  No file with that name exists in both images.'); continue
        shown = both[:30]
        for i, path in enumerate(shown, 1):
            print(f'    {i}  {path}   (before {b[path]}, after {a[path]})')
        if len(both) > 30:
            print(f'    ... {len(both) - 30} more; use a longer search text to narrow the list.')
        text = _ask('  Numbers to add, separated by commas, or "all" (Enter = none): ')
        picks = range(1, len(shown) + 1) if text.lower() == 'all' else [int(x) for x in re.findall(r'\d+', text)]
        for i in picks:
            if 1 <= i <= len(shown):
                entries[shown[i - 1]] = dict(label=shown[i - 1], before_id=b[shown[i - 1]], after_id=a[shown[i - 1]])
        print(f'  {len(entries)} file(s) selected so far.')
    if not entries:
        return None
    handle, name = tempfile.mkstemp(suffix='.json', prefix='streams-')
    with os.fdopen(handle, 'w', encoding='utf-8') as f:
        json.dump(list(entries.values()), f, indent=2)
    return Path(name)


def open_folder(path):
    try:
        if sys.platform.startswith('win'): os.startfile(str(path))
        elif sys.platform == 'darwin': subprocess.run(['open', str(path)])
        else: subprocess.run(['xdg-open', str(path)])
    except Exception:
        print(f'  Open it manually: {path}')


def run_job(mode, before, after, folder, offset, manifest):
    out = default_output(before, after)
    labels = {1: 'Quick comparison', 2: 'Full comparison (filesystem mapping)',
              3: 'Full comparison + selected files'}
    print('\nREADY TO RUN')
    print(f'  Image 1 (before) : {before}')
    print(f'  Image 2 (after)  : {after}')
    print(f'  Mode             : {labels[mode]}')
    if mode > 1: print(f'  Partition start  : sector {offset:,}')
    if manifest: print(f'  Selected files   : {len(json.loads(Path(manifest).read_text(encoding="utf-8")))}')
    print(f'  Results folder   : {out}')
    if _ask('\n  Press Enter to start, or type q to go back to the menu: ').lower() == 'q':
        return None
    a = argparse.Namespace(before=before, after=after, output=out, sector_size=512, buffer_mib=8,
                           filesystem=mode > 1, partition_offset=offset if mode > 1 else None,
                           tsk_bin=folder or None, streams=manifest)
    code = execute(a)
    if manifest and out.exists():
        shutil.copy(manifest, out / 'streams-manifest.json')
        if str(manifest).startswith(tempfile.gettempdir()): Path(manifest).unlink(missing_ok=True)
    if code != 0:
        print('  The run did not finish. Read the message above, then try again.'); return code
    q = lambda x: f'"{x}"'
    cmd = f'python tracediff.py compare {q(before)} {q(after)}'
    if mode > 1:
        cmd += f' --filesystem --partition-offset {offset}' + (f' --tsk-bin {q(folder)}' if folder else '')
    if manifest: cmd += f' --streams {q(out / "streams-manifest.json")}'
    print('\n  To repeat this run without the menu, type:\n    ' + cmd)
    if _ask('\n  Open the results folder now? [Y/n]: ').lower() in ('', 'y', 'yes'):
        open_folder(out)
    return 0


def check_setup():
    print('\nSETUP CHECK')
    print(f'  Python            : {sys.version.split()[0]} ' + ('(OK)' if sys.version_info >= (3, 10) else '(too old: 3.10 or newer is needed)'))
    print(f'  Tool folder       : {TOOL_DIR}')
    IMAGES_DIR.mkdir(exist_ok=True)
    count = sum(1 for f in IMAGES_DIR.iterdir() if f.is_file() and f.suffix.lower() not in NOT_IMAGES)
    print(f'  Images folder     : {IMAGES_DIR}  ({count} image file(s) found)')
    found, folder = find_tsk()
    if found:
        print('  The Sleuth Kit    : found' + (f' in {folder}' if folder else ' (on PATH)'))
    else:
        print(f'  The Sleuth Kit    : NOT found. Only menu option 1 will work.\n    Download it from {TSK_URL}\n    Unzip it, then choose menu option 2 and paste its "bin" folder when asked.')


def wizard():
    while True:
        _title(f'TraceDiff {VERSION}   Forensic comparison of two raw images')
        print(' What do you want to do?\n')
        print('   1  Quick comparison')
        print('        Hashes, sector, byte and bit differences. Nothing else to install.')
        print('   2  Full comparison')
        print('        Adds filesystem mapping. Needs The Sleuth Kit.')
        print('   3  Full comparison + compare selected files')
        print('        Also checks chosen files byte for byte. Needs The Sleuth Kit.')
        print('   4  Check my setup')
        print('   5  Show the full instructions')
        print('   6  Exit')
        choice = _ask('\n Enter 1, 2, 3, 4, 5 or 6: ')
        if choice == '6':
            return 0
        if choice == '4':
            check_setup(); continue
        if choice == '5':
            print(__doc__); continue
        if choice not in ('1', '2', '3'):
            print(' Please enter a number from 1 to 6.'); continue
        try:
            result = _guided_run(int(choice))
        except GoBack:
            print('  Back to the main menu.'); continue
        if result is not None:
            return result  # a run finished: exit, no second menu


def _guided_run(mode):
    """The guided steps for menu options 1 to 3. Returns an exit code, or None if cancelled."""
    folder, offset, manifest = '', 0, None
    if mode > 1:
        print('\nSTEP: checking for The Sleuth Kit')
        ok, folder = ensure_tsk()
        if not ok:
            return None
    images = choose_images()
    if not images:
        return None
    if mode > 1:
        offset = choose_partition(folder, images[0])
    if mode == 3:
        manifest = choose_streams(folder, images[0], images[1], offset)
        if manifest is None:
            mode = 2
    return run_job(mode, images[0], images[1], folder, offset, manifest)


def main():
    if len(sys.argv)==1:
        return wizard()
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--version',action='version',version=VERSION)
    sub=p.add_subparsers(dest='command',required=True)
    c=sub.add_parser('compare',help='Compare equal-length raw storage images.')
    c.add_argument('before',type=Path,metavar='IMAGE_1',help='Path to the BEFORE (baseline) raw image.')
    c.add_argument('after',type=Path,metavar='IMAGE_2',help='Path to the AFTER raw image.')
    c.add_argument('--output',type=Path,help='Results folder (must not exist). Default: results/<image1>_vs_<image2>_<date-time> inside the tool folder.')
    c.add_argument('--sector-size',type=int,default=512,help='Logical sector size in bytes (use 4096 for 4K-native media).')
    c.add_argument('--buffer-mib',type=int,default=8)
    c.add_argument('--filesystem',action='store_true',help='Map changed units with TSK (NTFS/FAT). Needs The Sleuth Kit.')
    c.add_argument('--partition-offset',type=int,help='Selected volume start, in raw image logical sectors; use 0 for a filesystem at image start.')
    c.add_argument('--tsk-bin',help='Folder containing The Sleuth Kit executables.')
    c.add_argument('--streams',type=Path,help='JSON list with label, before_id, after_id for selected streams. Needs The Sleuth Kit.')
    a=p.parse_args()
    if a.output is None: a.output=default_output(a.before,a.after)
    if a.output.exists(): p.error('Output directory already exists. Choose a new directory.')
    if (a.filesystem or a.streams) and (a.partition_offset is None or a.partition_offset<0):
        p.error('Filesystem/stream analysis requires an explicit nonnegative --partition-offset.')
    for label,path in (('Image 1',a.before),('Image 2',a.after)):
        if not path.is_file(): p.error(f'{label} was not found: {path}\nCheck the path and keep it inside quotes.')
    if a.filesystem or a.streams:
        missing=missing_tsk(a.tsk_bin)
        if missing: p.error(TSK_HELP.format(missing=', '.join(missing)))
    return execute(a)

if __name__=='__main__': sys.exit(main())
