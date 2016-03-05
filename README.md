# ngx_brotli_module

This NGINX module enables the brotli compression for Accept-Encoding:"brotli".

Brotli is a recent compression format developed by Google.

http://www.ietf.org/id/draft-alakuijala-brotli-06.txt

The module comes with a bundled encoder from https://github.com/google/brotli 
with a C wrapper.

Use the `--add-module=` when configuring NGINX to enable the module.

Config options:

`brotli on/off;`   - enable the module. When brotli is enabled, it takes
                  precedence over gzip if Accept-Encoding has both gzip and
                  brotli.

`brotli_comp_level  num;`  - the compression level used `1-11`

`brotli_min_length  num;`  - the minimal size of the resource to be compressed.
                          Brotli will compress only resources larger than this
                          value. If it is smaller it will let gzip to compress.

Currently tested only on Linux.
