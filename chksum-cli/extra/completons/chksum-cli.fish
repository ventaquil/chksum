#!/usr/bin/env fish

complete --command chksum-cli --short-option h --long-option help --description 'Prints help information'
complete --command chksum-cli --short-option H --long-option hash --arguments 'MD5 SHA1 SHA-1 SHA256 SHA-256 SHA2 256 SHA-2 256' --exclusive --description 'Choose hashing algorithm'
complete --command chksum-cli --short-option s --long-option chunk-size --exclusive --description 'Set chunk size of processing data'
complete --command chksum-cli --short-option V --long-option version --description 'Prints version information'
