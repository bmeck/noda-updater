const task = require('generator-runner');
const hyperquest = require('hyperquest');
const concat = require('concat-stream');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const semver = require('semver');
const tmp = require('tmp');
const minimatch = require('minimatch');

/*
check({
  currentVersion: '1.0.0',
  distUrl: 'https://iojs.org/dist',
  *approveFilename(filename) { return minimatch(filename, '**darwin*tar.gz'); },
  //*approveVersion(version) { return true } 
}, (err, ret) => {
  if (err) console.error(`error: ${err.stack}`);
  else console.log(`return: ${ret}`);
});
*/

class Cleanup {
  constructor() {
    this.todo = null;
    this.finished = false;
  }

  add(fn) {
    if (this.finished) {
      fn();
    }
    if (this.todo != null) {
      this.todo.push(fn);
    }
    else {
      this.todo = [fn];
    }
  }

  finish() {
    if (this.finished) {
      throw new Error('already finished');
    }
    this.finished = true;
    for (let action of this.todo) {
      action();
    }
    this.todo = null;
  }
}

function check({
    currentVersion,
    distUrl,
    approveFilename,
    approveVersion = function* () { return true; }
  }, cb) {
  task(function* () {
    let cleanup = new Cleanup();
    try {
      let {tmp_dir, best_version} = yield {
        tmp_dir: _ => tmp.dir({
	  unsafeCleanup:true
	}, (err, path, dispose) => {
	  cleanup.add(dispose);
	  _(err, path);
	}),
        best_version: getVersionFromDist(distUrl, currentVersion, approveVersion) 
      }

      let version_url = `${distUrl}/${best_version.version}`;

      // gc
      best_version = null;

      // write encrypted key to key_file
      let key_url = `${version_url}/SHASUMS256.txt.gpg`;
      let key_file = path.join(tmp_dir, 'key.gpg');
      let keyring = path.join(tmp_dir, 'keyring');

      let cleartext_sig_url = `${version_url}/SHASUMS256.txt`;

      let {cleartext_sig_body} = yield {
        keyring_imported: downloadAndImportKey(key_url, key_file, keyring),
        cleartext_sig_body: downloadAsString(cleartext_sig_url)
      };


      // download encrypted signatures and transform them to cleartext
      let encrypted_sig_url = `${version_url}/SHASUMS256.txt.asc`;
      let decrypted_sig_body = yield decryptStream(hyperquest(encrypted_sig_url), keyring);

      if (decrypted_sig_body !== cleartext_sig_body) {
	throw new Error('signature decryption did not match cleartext');
      }
      // gc
      cleartext_sig_body = null;

      let signatures = decrypted_sig_body.trim().split(/\n/g).map(line => {
	let [checksum, filepath] = line.trim().split(/\s+/);
	return {checksum, filepath};
      });

      let downloadable_files = yield getApprovedSignatures(signatures, approveFilename);
      if (downloadable_files.length === 0) {
        throw new Error('no file was approved to download');
      }

      let resource_file = path.join(tmp_dir, 'resource');
      for (let download of downloadable_files) {
	let download_url = `${version_url}/${download.filepath}`
	let download_file_stream = fs.createWriteStream(resource_file);

        yield waitOnStreamOpen(download_file_stream);

	// shell out because crypto cannot update list of algorithms (future safety)
	let checksum_child = cp.spawn('shasum', ['-a', '256', '-']);
	let download_http_stream = hyperquest(download_url);
	download_http_stream.pipe(checksum_child.stdin);
	download_http_stream.pipe(download_file_stream);

	let {checksum_body} = yield {
	  download: waitOnWriteStream(download_file_stream),
	  checksum_code: waitOnChild(checksum_child, 'shasum'),
	  checksum_body: concatStream(checksum_child.stdout) 
	};

	if (checksum_body.split(/\s+/)[0] !== download.checksum) {
	  throw new Error(`checksum mismatch on ${download_url}`);
	}

	let final_stream = fs.createReadStream(resource_file);

        yield waitOnStreamOpen(final_stream);

	return {
	  from: download_url,
	  stream: final_stream,
	  checksum: download.checksum
	};
      }
    }
    finally {
      cleanup.finish();
    }
  }, cb);
}

function* downloadAsString(url) {
  let stream = hyperquest(url);
  return yield concatStream(stream);
}

function waitOnChild(child, name = 'child process') {
  return _ => {
    child.on('exit', (code, signal) => {
      if (code) _(new Error(`${name} failed with code: ${code}`));
      else if (signal) _(new Error(`${name} failed with signal: ${signal}`));
      else _(null);
    });
  }
}
function waitOnWriteStream(stream) {
  return _ => {
    stream
    .on('finish', () => _(null, null) )
    .on('error', err => _(err, undefined));
  }
}

function concatStream(stream) {
  return _ => {
    stream.pipe(concat(
      (body) => _(null, String(body)) 
    ))
    .on('error', (err) => _(err, undefined));
  }
}

function waitOnStreamOpen(stream) {
  return _ => {
    function onerror(e) {
      _(e, undefined);
    }
    function onopen() {
      stream.removeListener('error', onerror);
      _(null, undefined);
    }
    stream.on('open', onopen);
    stream.on('error', onerror);
  }
}

function* getVersionFromDist(distUrl, currentVersion, approveVersion) {
  let body = yield downloadAsString(`${distUrl}/index.json`);
  let approved = [];
  let versions = JSON.parse(body);
  for (let version of versions) {
    let approval = yield approveVersion(version);
    let newer = semver.gt(version.version, currentVersion)
    if (approval && newer) {
      approved.push(version);
    }
  }
  if (approved.length === 0) {
    return null;
  }

  let best_version = yield getBestVersion(approved);

  return best_version;
}

function* getBestVersion(versionArray, approveVersion) {
  let best_version = versionArray[0];
  let best_version_str = best_version.version.slice(1);

  for (let version of versionArray) {
    let version_str = version.version.slice(1);
    if (semver.gt(version_str, best_version_str)) {
      best_version = version;
      best_version_str = version_str;
    }
  }

  return best_version;
}

function* getApprovedSignatures(signatures, approveFilename) {
  let approved_signatures = [];
  for (let signature of signatures) {
    let approved = yield approveFilename(signature.filepath);
    if (approved) {
      approved_signatures.push(signature);
    }
  }

  return approved_signatures;
}

function* downloadAndImportKey(key_url, key_file, keyring) {
  let key_body = yield downloadAsString(key_url);
  yield _ => fs.writeFile(key_file, key_body, _);

  // create a pgp keyring we can use with the key
  yield _ => cp.exec(`gpg --no-default-keyring --primary-keyring ${keyring} --import ${key_file}`, _);
}

function* decryptStream(stream, keyring) {
  let child = cp.spawn('gpg', ['--no-default-keyring', '--primary-keyring', keyring]);
  stream.pipe(child.stdin);
  let {code, decrypted_sig_body} = yield {
    code: waitOnChild(child, 'gpg'),
    decrypted_sig_body: concatStream(child.stdout)
  };
  return decrypted_sig_body;
}
