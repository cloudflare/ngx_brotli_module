cat << END                                                >> $NGX_MAKEFILE

$ngx_addon_dir/brotli_encoder/libbrotli.a:   $NGX_MAKEFILE
	cd $ngx_addon_dir/brotli_encoder \\
	&& \$(MAKE)

END

