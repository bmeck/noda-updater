# noda-updater
noda spec for updating a resource

this is used for updating the runtime or the codebase of a single binary executable generally.

## Update Check Steps

```
given $url
given $known_key
given $name_pattern
given $acceptable_version_fn
get https://$url/index.json as $versions
filter $versions on $acceptable_version_fn
find $versions max(.version) as $version
set $version_url to $url/$version
get $version_url/SHASUM$ALGO.txt/gpg as $remote_key
get $version_url/SHASUM$ALGO.txt/asc as $remote_signatures
if $remote_key is not $known_key
  fail: key mismatch
decrypt $remote_signatures using $known_key as $sha_list[.sha .path]
find $name_pattern in $sha_list by .name as $executable_info
get $version_url/$executable_info.path as $executable
shasum $executable as $executable_sha
if  $executable_sha is not $executable_info.sha
  fail: sha mismatch
success: $executable
```

