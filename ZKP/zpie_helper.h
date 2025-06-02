#ifndef ZPIE_HELPERS_H
#define ZPIE_HELPERS_H

#include "zpie.h"

void circuit()
{
    element out;
    init_public(&out);

    element a, b;
    init(&a);
    init(&b);

    input(&a, "32416190071");   
    input(&b, "32416187567");   

    mul(&out, &a, &b);
}

#endif