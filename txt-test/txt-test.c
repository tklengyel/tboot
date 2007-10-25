/*
 * txt-test: Linux kernel module that will display various information about
 *           the status of TXT.  It also indicates whether the various TXT
 *           memory regions are protected from access by the kernel.
 *
 * Copyright (c) 2006-2007, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdbool.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <asm/io.h>
#include <asm/page.h>
#include "../include/uuid.h"
#include "../include/tboot.h"
#include "../tboot/include/tpm.h"
#include "../tboot/include/txt/config_regs.h"

/* device name for Intel(r) TXT device we create */
#define DEVICE_NAME       "txt"

static struct file_operations fops;
static int dev_major;

#define TBOOT_MEM_BASE      (0x70000 - 3*PAGE_SIZE)
                               /* 0x90000 is Xen's start of trampoline code */
#define TBOOT_MEM_SIZE      (0x90000 - TBOOT_MEM_BASE)

#define TXT_CONFIG_REGS_SIZE        (NR_TXT_CONFIG_PAGES*PAGE_SIZE)
#define TPM_LOCALITY_SIZE           (NR_TPM_LOCALITY_PAGES*PAGE_SIZE)

#define TPM_REG_ACCESS				0x00000000

static inline uint64_t read_txt_config_reg(void *config_regs_base,
                                           uint32_t reg)
{
    /* these are MMIO so make sure compiler doesn't optimize */
    return *(volatile uint64_t *)(config_regs_base + reg);
}

static void display_config_regs(void *txt_config_base)
{
    printk("Intel(r) TXT Configuration Registers:\n");

    /* STS */
    printk("\tSTS: 0x%Lx\n", read_txt_config_reg(txt_config_base, TXTCR_STS));

    /* ESTS */
    printk("\tESTS: 0x%Lx\n", read_txt_config_reg(txt_config_base,
                                                  TXTCR_ESTS));

    /* E2STS */
    printk("\tE2STS: 0x%Lx\n", read_txt_config_reg(txt_config_base,
                                                   TXTCR_E2STS));

    /* ERRORCODE */
    printk("\tERRORCODE: 0x%Lx\n", read_txt_config_reg(txt_config_base,
                                                       TXTCR_ERRORCODE));

    /* DIDVID */
    printk("\tDIDVID: 0x%Lx\n", read_txt_config_reg(txt_config_base,
                                                    TXTCR_DIDVID));

    /* SINIT.BASE/SIZE */
    printk("\tSINIT.BASE: 0x%Lx\n", read_txt_config_reg(txt_config_base,
                                                        TXTCR_SINIT_BASE));
    printk("\tSINIT.SIZE: 0x%Lx\n", read_txt_config_reg(txt_config_base,
                                                        TXTCR_SINIT_SIZE));

    /* HEAP.BASE/SIZE */
    printk("\tHEAP.BASE: 0x%Lx\n", read_txt_config_reg(txt_config_base,
                                                       TXTCR_HEAP_BASE));
    printk("\tHEAP.SIZE: 0x%Lx\n", read_txt_config_reg(txt_config_base,
                                                       TXTCR_HEAP_SIZE));
}

static void display_tboot_log(void *txt_config_base)
{
    void *tb_base, *curr;
    tboot_log_t *log;
    static char buf[512];
    int curr_pos;

    /* need to map TBOOT's memory before we can search for log */
    tb_base = (void *)ioremap_nocache(TBOOT_MEM_BASE, TBOOT_MEM_SIZE);

    if ( tb_base == NULL ) {
        printk(KERN_ALERT
               "ERROR: unable to map TBOOT to find log\n");
        return;
    }

    curr = tb_base;
    do {
        if ( are_uuids_equal(curr, &((uuid_t)TBOOT_LOG_UUID)) )
            break;
        curr++;
    } while ( curr < tb_base + TBOOT_MEM_SIZE );

    if ( curr >= tb_base + TBOOT_MEM_SIZE ) {
        printk("unable to find TBOOT log\n");
        return;
    }
    log = (tboot_log_t *)curr;

    printk("TBOOT log:\n");
    printk("\t max_size=%x\n", log->max_size);
    printk("\t curr_pos=%x\n", log->curr_pos);
    printk("\t buf:\n");
    /* log is too big for single printk(), so break it up */
    for ( curr_pos = 0; curr_pos < log->curr_pos; curr_pos += sizeof(buf)-1 ) {
        strncpy(buf, log->buf + curr_pos, sizeof(buf)-1);
        buf[sizeof(buf)-1] = '\0';
        printk(buf);
    }
    printk("\n");

    iounmap(tb_base);
}

static bool test_access_txt_priv_config(void)
{
    void *ptr = NULL;

    printk("testing for access to TXT private config space...\n");

	/* try to get pointer to TXT private config space */
    ptr = (void *)ioremap_nocache(TXT_PRIV_CONFIG_REGS_BASE,
                                  TXT_CONFIG_REGS_SIZE);
    if ( ptr == NULL )
        printk(KERN_ALERT "ERROR: ioremap_nocache for private space failed\n");
    else {
        printk(KERN_ALERT "ioremap_nocache for private space succeeded\n");
        iounmap(ptr);
    }
    return (ptr == NULL);
#if 0
	/* try using hypercall */
	{
	  struct xen_domctl domctl = { 0 };
	  privcmd_hypercall_t hypercall = { 0 };
	  int ret = -1;

	  domctl.cmd = XEN_DOMCTL_iomem_permission;
	  domctl.domain = DOMID_DOM0;
	  domctl.u.iomem_permission.first_mfn = 0xfed20;
	  domctl.u.iomem_permission.nr_mfns = 0x10;
	  domctl.u.iomem_permission.allow_access = 1;
	  domctl->interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	  hypercall.op     = __HYPERVISOR_domctl;
	  hypercall.arg[0] = (unsigned long)domctl;

	  ret = ioctl(xc_handle, IOCTL_PRIVCMD_HYPERCALL,
			   (unsigned long)hypercall);
	  if ( ret < 0 )
	    printk(KERN_ALERT "\nERROR: failed to set iomem permissions\n");
	  else {
	    if ((PrivatePtr = (void *)ioremap_nocache(0xFED20000, 0x1000)) == NULL)
	      printk(KERN_ALERT "\nERROR: ioremap_nocache for private space failed\n\n");
	    else {
	      printk(KERN_ALERT "ioremap_nocache for private space succeeded\n");
	      iounmap(PrivatePtr);
	    }
	  }
	}
#endif
}

static bool test_access_tpm_localities(void)
{
    int locality;
    void *base, *ptr=NULL;
    int access;

    printk("testing for access to TPM localities "
           "(ff = locality unavailable):\n");

    for ( locality = 0; locality < TPM_NR_LOCALITIES; locality++ ) {
        base = (void *)(unsigned long)TPM_LOCALITY_BASE_N(locality);
        ptr = (void *)ioremap_nocache((unsigned long)base, TPM_LOCALITY_SIZE);
        if ( ptr == NULL ) {
            printk(KERN_ALERT
                   "ERROR: ioremap_nocache for TPM locality %d failed\n",
                   locality);
            return false;
        }

        access = readb(ptr + TPM_REG_ACCESS);
        printk(KERN_ALERT "TPM: Locality %d access = %x\n", locality, access);

        iounmap(ptr);
    }

    return true;
}

static bool test_access_txt_heap(void *txt_config_base)
{
    void *ptr;
    uint64_t base, size;

    printk("testing for access to SINIT and TXT heap memory...\n");

    /* SINIT */
    base = read_txt_config_reg(txt_config_base, TXTCR_SINIT_BASE);
    size = read_txt_config_reg(txt_config_base, TXTCR_SINIT_SIZE);
    ptr = (void *)ioremap_nocache(base, size);
    if ( ptr == NULL ) {
        printk(KERN_ALERT
               "ERROR: ioremap_nocache for SINIT failed\n");
    }
    else {
        printk(KERN_ALERT "ioremap_nocache for SINIT succeeded\n");
        iounmap(ptr);
        return false;
    }

    /* TXT heap */
    base = read_txt_config_reg(txt_config_base, TXTCR_HEAP_BASE);
    size = read_txt_config_reg(txt_config_base, TXTCR_HEAP_SIZE);
    ptr = (void *)ioremap_nocache(base, size);
    if ( ptr == NULL ) {
        printk(KERN_ALERT
               "ERROR: ioremap_nocache for TXT heap failed\n");
        return true;
    }
    else {
        printk(KERN_ALERT "ioremap_nocache for TXT heap succeeded\n");
        iounmap(ptr);
        return false;
    }
}

static bool test_access_tboot(void)
{
    void *ptr;

    printk("testing for access to tboot memory...\n");

    ptr = (void *)ioremap_nocache(TBOOT_MEM_BASE, TBOOT_MEM_SIZE);
    if ( ptr == NULL ) {
        printk(KERN_ALERT
               "ERROR: ioremap_nocache for tboot failed\n");
        return true;
    }
    else {
        printk(KERN_ALERT "ioremap_nocache for tboot succeeded\n");
        iounmap(ptr);
        return false;
    }
}

static bool is_txt_supported(void)
{
    return true;
}

static __init int mod_init(void)
{
    void *txt_pub = NULL;

    if ( !is_txt_supported() ) {
        printk(KERN_ALERT "Intel(r) TXT is not supported\n");
        return 0;
    }

    /* make sure no one else has grabbed the public config space */
    if ( check_mem_region(TXT_PUB_CONFIG_REGS_BASE, TXT_CONFIG_REGS_SIZE) ) {
        printk(KERN_ALERT
               "ERROR: TXT public config space is already reserved\n");
        return -EBUSY;
    }

    /* register a TXT device (let kernel pick major #) */
	dev_major = register_chrdev(0, DEVICE_NAME, &fops); 
	if ( dev_major < 0 ) {
	    printk (KERN_ALERT "ERROR: failed to create TXT device (%d)\n",
                dev_major); 
	    return 0;
	}

    /*
     * display config regs
     */
	if ( request_mem_region((unsigned long)TXT_PUB_CONFIG_REGS_BASE,
                            TXT_CONFIG_REGS_SIZE, DEVICE_NAME) == 0 ) {
		printk(KERN_ALERT
               "ERROR: request_mem_region for public space failed\n");
        goto done;
	}
    txt_pub = (void *)ioremap_nocache(TXT_PUB_CONFIG_REGS_BASE,
                                      TXT_CONFIG_REGS_SIZE);
    if ( txt_pub == NULL ) {
		printk(KERN_ALERT "ERROR: ioremap_nocache for public space failed\n");
        goto done;
	}
    display_config_regs(txt_pub);

    /*
     * display the TBOOT log
     */
    display_tboot_log(txt_pub);

    /*
     * begin tests
     */
    test_access_txt_priv_config();

    test_access_tpm_localities();

    test_access_txt_heap(txt_pub);

    test_access_tboot();

 done:
    if ( txt_pub != NULL )
        iounmap(txt_pub);
    release_mem_region(TXT_PUB_CONFIG_REGS_BASE, TXT_CONFIG_REGS_SIZE);
    unregister_chrdev(dev_major, DEVICE_NAME); 
    return 0;
}

static __exit void mod_exit(void)
{
    printk("txt-test module unloading\n");
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("BSD");


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
