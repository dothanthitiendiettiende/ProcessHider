//
//  ProcHider.c
//  ProcHider
//
//  Created by Folker Schwesinger on 17.05.13.
//  Copyright (c) 2013 rkd. All rights reserved.
//

#include <mach/mach_types.h>

kern_return_t ProcHider_start(kmod_info_t * ki, void *d);
kern_return_t ProcHider_stop(kmod_info_t *ki, void *d);

kern_return_t ProcHider_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t ProcHider_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
