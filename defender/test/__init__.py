import requests

import tarfile
import zipfile
import pathlib

import time
import tqdm
import json

import numpy as np
import os

MAXFILESIZE = 2**21  # 2 MiB
TIMEOUT = 5
ZIP_PASSWORDS = [b'', b'infected']

# TINY PE FILES
MZHEADER = b'MZ'

TINYPE97 = (b'MZ\x00\x00PE\x00\x00L\x01\x01\x00j*X\xc3\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x04\x00\x03\x01\x0b\x01\x08\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00'
            b'\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x00\x0c\x00\x00\x00\x00\x00@\x00\x04'
            b'\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00'
            b'\x00\x00\x00\x00\x00h\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00\x02')

TINYIMPORT = (b'MZ\x00\x00PE\x00\x00L\x01\x01\x00j*X\xc3\x00\x00\x00\x00\x00\x00\x00\x00'
              b'\x04\x00\x03\x01\x0b\x01\x08\x00\x98\x00\x00\x00\x00\x00\x00\x00\x95\x00'
              b'\x00\x00\x0c\x00\x00\x00\x95\x00\x00\x00\x0c\x00\x00\x00\x00\x00@\x00\x04'
              b'\x00\x00\x00\x04\x00\x00\x00\x94\x00\x00\x00\x8c\x00\x00\x00\x04\x00\x00'
              b'\x00\x00\x00\x00\x00$\x01\x00\x00\x8c\x00\x00\x00\x00\x00\x00\x00\x02\x00'
              b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
              b'\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x008\x00\x00'
              b'\x00(\x00\x00\x00\x01\x00\x00\x80\x00\x00\x00\x00KERNEL32.dll\x00')


def file_bytes_generator(location, maxsize, return_filename=True):
    # yields (name,bytes) for files smaller than `maxsize` and that begin with b'MZ'
    # works for tar (including bz2, gz), zip, and directories
    path = pathlib.Path(location)
    if path.is_file():
        if location.lower().endswith('.zip'):
            pwd_ix = 0
            with zipfile.ZipFile(location, 'r') as f:
                for info in f.infolist():
                    if info.file_size <= maxsize:
                        while True:
                            try:
                                content = f.read(
                                    info.filename, pwd=ZIP_PASSWORDS[pwd_ix])
                            except RuntimeError:
                                pwd_ix += 1
                                if pwd_ix >= len(ZIP_PASSWORDS):
                                    raise Exception(
                                        f"Unable to guess ZIP encryption passwords for {location}")
                            else:
                                break

                        if content.startswith(b'MZ'):
                            yield (os.path.join(location, info.filename), content) if return_filename else content

        elif location.lower().endswith('.tar') or location.lower().endswith('.tar.bz2') or location.lower().endswith('.tar.gz') or location.lower().endswith('.tgz'):
            with tarfile.open(location, mode='r') as tar:
                for member in tar:
                    if member.size <= maxsize:
                        f = tar.extractfile(member)
                        if f:
                            content = f.read()
                            if content.startswith(b'MZ'):
                                yield (os.path.join(location, member.name), content) if return_filename else content

    elif path.is_dir():
        for filepath in path.glob('*'):
            fileobj = pathlib.Path(filepath)
            if fileobj.is_file() and fileobj.stat().st_size <= maxsize:
                try:
                    with open(filepath, 'rb') as infile:
                        content = infile.read()
                        if content.startswith(b'MZ'):
                            yield (fileobj.absolute().name, content) if return_filename else content
                except PermissionError:
                    continue


def get_raw_result(bytez, url, timeout):
    return requests.post(url, data=bytez, headers={'Content-Type': 'application/octet-stream'}, timeout=timeout)


def get_result(bytez, url, timeout, raise_exception=False):
    error_msg = None
    res = None
    start = time.time()
    try:
        res = get_raw_result(bytez, url, timeout)
        result = res.json()['result']
    except (requests.RequestException, KeyError, json.decoder.JSONDecodeError) as e:
        result = 0  # timeout or other error results in benign
        error_msg = str(e)
        if res:
            error_msg += f'-{res.text()}'
        if raise_exception:
            raise(e)

    elapsed = time.time() - start

    return result, elapsed, error_msg


def measure_efficacy(benignfiles, maliciousfiles, url, maxfilesize, timeout, silent=False, stop_after=None, raise_exception=False):
    y_true = []
    y_pred = []
    elapsed = []
    error = []
    fps = []
    fns = []
    errors = []

    for i, (fname, bytez) in tqdm.tqdm(enumerate(file_bytes_generator(maliciousfiles, maxfilesize)), desc="malicious", disable=silent):
        if stop_after and i >= stop_after:
            break
        y_true.append(1)
        y, t, e = get_result(bytez, url, timeout, raise_exception)
        y_pred.append(y)
        elapsed.append(t)
        error.append(0 if e is None else 1)
        if e:
            errors.append((fname, e))
        if y != 1:
            fns.append(fname)

    for i, (fname, bytez) in tqdm.tqdm(enumerate(file_bytes_generator(benignfiles, maxfilesize)), desc="benign", disable=silent):
        if stop_after and i >= stop_after:
            break
        y_true.append(0)
        y, t, e = get_result(bytez, url, timeout, raise_exception)
        y_pred.append(y)
        elapsed.append(t)
        error.append(0 if e is None else 1)
        if e:
            errors.append((fname, e))
        if y != 0:
            fps.append(fname)

    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    elapsed = np.array(elapsed)
    error = np.array(error)

    summary = {
        'tested': len(y_true),
        'malicious': int(np.sum(y_true == 1)),
        'benign': int(np.sum(y_true == 0)),
        'fp': float(len(fps) / np.sum(y_true == 0)),
        'fn': float(len(fns) / np.sum(y_true == 1)),
        'errors': int(sum(error)),  # includes timeouts and other errors
        'max_time': float(elapsed.max()),
        'avg_time': float(np.mean(elapsed))
    }

    return summary, fps, fns, errors


def informational(url, timeout):
    def get_json_string_result_for(bytez):
        res = get_raw_result(bytez, url, timeout)
        return json.dumps(res.json())

    result = f'''
    Preliminary tests:
    \tMZ header: {get_json_string_result_for(MZHEADER)}
    \tTiny PE FILE with no imports: {get_json_string_result_for(TINYPE97)}
    \tTiny PE FILE with import: {get_json_string_result_for(TINYIMPORT)}'''

    return result


if __name__ == '__main__':
    from collections import defaultdict
    usernum = defaultdict(lambda: len(usernum))
    import zipfile
    import glob
    for zfn in sorted(glob.glob('zip/*.zip')):
        with zipfile.ZipFile(zfn, 'r') as f:
            for info in f.infolist():
                if info.file_size <= 2**21:
                    content = f.read(info.filename)

                    if not content.startswith(b'MZ'):
                        break

                    # create a sensible output filename:
                    # 023_u0_ts0
                    base = zfn[:-len('.zip.filtered.zip')]
                    ix = base.rfind('_')
                    ts, num = base[ix + 1:].split('.')
                    user = base[:ix]
                    num = num.zfill(3)

                    base = info.filename
                    if base not in {str(n).zfill(3) for n in range(1, 50)}:
                        break

                    user = str(usernum[user]).zfill(3)

                    outname = f'{base}_u{user}_s{num}'
                    print(f'{zfn}/{info.filename} -> {outname}')
                    with open(outname,'wb') as outf:
                        outf.write(content)
                    