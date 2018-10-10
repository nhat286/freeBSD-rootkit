# Homebrew binaries

#### How ?

- Clone the coreutils repo somewhere (contains source files like `ls.c`)
    ```
    git clone git://git.sv.gnu.org/coreutils
    ```    
- Try and compile using `gcc -static source.c -o outfile`
    - Most likely it will complain about missng `config.h`
- Just run `./bootstrap` and ./configure` and `make` to build
    - Any errors or missing shit along the way, just install it or stack overflow it :) 
    - Uhhh might have to remove the `W=suggest-blah-const` from the Makefile 


#### Rootkit VM Sources location
```
/usr/src/sbin/md5/md5.c
/usr/src/bin/ls/ls.c
```

- Need to find a way to compile statically linked, running `make` will create all but according to the Makefile specs, we want to be able to compile our own ! 
