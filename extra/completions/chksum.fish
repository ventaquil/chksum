#!/usr/bin/env fish

complete --command chksum --short-option h --long-option help --description 'Prints help information'
complete --command chksum --short-option H --long-option hash --arguments 'MD5 SHA1 SHA-1' --exclusive --description 'Choose hashing algorithm'
complete --command chksum --short-option P --long-option with-paths --description 'Use paths to calculate digest'
complete --command chksum --short-option s --long-option chunk-size --exclusive --description 'Set chunk size of processing data'
complete --command chksum --short-option V --long-option version --description 'Prints version information'
