cat << END                                                >> $NGX_MAKEFILE

brotli: $NGX_MAKEFILE
	cd $ngx_addon_dir/brotli \\
	&& \$(MAKE)

END

