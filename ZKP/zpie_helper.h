#ifndef ZPIE_HELPERS_H
#define ZPIE_HELPERS_H

#include "zpie.h"

// Shared zk-SNARK circuit for proving a * b = out
void circuit()
{
    element out;
    init_public(&out);

    element a, b;
    init(&a);
    init(&b);

    input(&a, "1234");
    input(&b, "5678");

    mul(&out, &a, &b);
}

#endif
