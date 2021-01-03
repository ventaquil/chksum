#!/usr/bin/env fish

complete --command chksum --short-option h --long-option help --description 'Prints help information'
complete --command chksum --short-option v --long-option version --description 'Prints version information'
complete --command chksum --short-option j --long-option jobs --exclusive --description 'Chunk size'
complete --command chksum --short-option H --long-option hash --arguments 'MD5 SHA1' --exclusive --description 'Chosen hash algorithm'
complete --command chksum --short-option j --long-option jobs --arguments "(seq (nproc))" --exclusive --description 'Maximum number of working threads'
