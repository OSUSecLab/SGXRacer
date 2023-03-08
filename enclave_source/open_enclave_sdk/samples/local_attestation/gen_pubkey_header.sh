#!/usr/bin/env bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

destfile="$1"
pubkey_file="$2"

cat > "$destfile" << EOF
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef SAMPLES_LOCAL_ATTESTATION_PUBKEY_H
#define SAMPLES_LOCAL_ATTESTATION_PUBKEY_H

EOF

printf 'static const char OTHER_ENCLAVE_PUBLIC_KEY[] =' >> "$destfile"
while IFS="" read -r p || [ -n "$p" ]
do
    # Sometimes openssl can insert carriage returns into the PEM files. Let's remove those!
    CR=$(printf "\r")
    p=$(echo "$p" | tr -d "$CR")
    printf '\n    \"%s\\n\"' "$p" >> "$destfile"
done < "$pubkey_file"
printf ';\n' >> "$destfile"

cat >> "$destfile" << EOF

#endif /* SAMPLES_LOCAL_ATTESTATION_PUBKEY_H */
EOF
