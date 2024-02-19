#!/bin/bash

sed -i.bak -e 's/require("\(.*\).js")/require("\1.cjs")/g' dist/cjs/*.js

# Rename to .cjs
find dist/cjs -name '*.js' | xargs -I{} -n 1 bash -c 'mv $0 $(echo "$0" | cut -d. -f1).cjs' {}

# Remove backup files
find dist/cjs -name '*.bak' | xargs rm -f
