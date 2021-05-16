#!/usr/bin/env fish

complete --command chksum --short-option h --long-option help --description 'Prints help information'
complete --command chksum --short-option v --long-option version --description 'Prints version information'
complete --command chksum --short-option s --long-option chunk-size --exclusive --description 'Chunk size'
complete --command chksum --short-option H --long-option hash --arguments 'MD5 SHA1 SHA-1' --exclusive --description 'Chosen hash algorithm'
complete --command chksum --short-option P --long-option with-paths --description 'Use paths to calculate digests'
