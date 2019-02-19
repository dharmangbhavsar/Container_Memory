//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2018
//
////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
//
////////////////////////////////////////////////////////////////////////
//
//   Author:  Hung-Wei Tseng, Yu-Chia Liu
//
//   Description:
//     Core of Kernel Module for Processor Container
//
////////////////////////////////////////////////////////////////////////


#include "memory_container.h"

#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>

typedef struct Thread{
    struct task_struct *data;
    struct Thread *next;
};
typedef struct Object{
    unsigned long oid;
    void* address;
    unsigned long pfn;
    struct Object *next;
};
typedef struct Container{
    __u64 cid;
    struct Container *next;
    struct Thread *thread;
    struct Object *object;
    struct mutex container_lock;
};
struct Container *container = NULL;

void print_ds(void){
    struct Container *begin = container;
    struct Thread *begin_t = NULL;
    do{
        printk("=>Container - %d\n", begin->cid);
        if (begin->thread){
            begin_t = begin->thread;
            while(begin_t){
                printk("   - Thread : %d\n", begin_t->data->pid);
                if (!begin_t->next){
                    break;
                }
                begin_t = begin_t->next;
            }
        }
    if (begin->object){
            struct Object* begin_o = begin->object;
            while(begin_o){
                printk("   - Object : %llu - %d\n", begin_o->oid, begin_o->pfn);
                if (!begin_o->next){
                    break;
                }
                begin_o = begin_o->next;
            }
        }
        
        if (!begin->next){
            break;
        }
        begin = begin->next;
    }while(begin);
}

struct Container* get_container(void) {
    struct Container *begin = container;
    struct Thread *begin_t = NULL;
    do{
        if (begin->thread){
            begin_t = begin->thread;
            while(begin_t){
                if (begin_t->data->pid == current->pid) {
                    return begin;
                }
                if (!begin_t->next){
                    break;
                }
                begin_t = begin_t->next;
            }
        }
        
        if (!begin->next){
            break;
        }
        begin = begin->next;
    }while(begin);
    return NULL;
}

struct Object* get_object(struct Container* start, unsigned long long oid) {

    struct Object* begin_o = start->object;
    while (begin_o) {
        if (begin_o->oid == oid) {
            return begin_o;
        }
        begin_o = begin_o->next;
    }
    return NULL;
}

void set_object(struct Container* start, unsigned long long oid, void* addr, unsigned long pfn) {
     struct Object* obj = kcalloc(1, sizeof(struct Object), GFP_KERNEL);
     obj->oid = oid;
     obj->address = addr;
     obj->pfn = pfn;
     obj->next = NULL;

     if (start->object == NULL) {
        start->object = obj;
     } else {
        struct Object* begin_o = start->object;
        while (begin_o->next) {
            begin_o = begin_o->next;
        }
        begin_o->next = obj;
     }
}

int memory_container_mmap(struct file *filp, struct vm_area_struct *vma)
{
    //printk("---- MMAP ----\n"); 
    struct Container* start = get_container();
    unsigned long long oid = vma->vm_pgoff;

    struct Object* object = get_object(start, oid);
    
    unsigned long pfn = 0;

    if (object == NULL) {
        void *mem = kcalloc(1, (vma->vm_end-vma->vm_start), GFP_KERNEL);
        pfn = virt_to_phys((void*)mem)>>PAGE_SHIFT;
        set_object(start, oid, mem, pfn);
    } else {
        pfn = object->pfn;
    }
    int rmap = remap_pfn_range(vma, vma->vm_start, pfn, vma->vm_end - vma->vm_start, vma->vm_page_prot);
    return 0;
}


int memory_container_lock(struct memory_container_cmd __user *user_cmd)
{
    //printk("---- LOCK ----\n");
    struct Container *start = get_container();
    mutex_lock(&(start->container_lock));
    return 0;
}


int memory_container_unlock(struct memory_container_cmd __user *user_cmd)
{
    //printk("---- UNLOCK ----\n");
    struct Container *start = get_container();
    mutex_unlock(&(start->container_lock));
    return 0;
}


int memory_container_delete(struct memory_container_cmd __user *user_cmd)
{
    //printk("---- DELETE ----\n");
    struct memory_container_cmd temp;
    copy_from_user(&temp, user_cmd, sizeof(struct memory_container_cmd));
    __u64 cid = temp.cid;

    struct Container *start = get_container();

    if(!(start->thread)) return 0;

    struct Thread *th = NULL;

    if (start->thread->data->pid == current->pid) {
        th = start->thread;
        start->thread = start->thread->next;
    } else {
        struct Thread *t_start = start->thread;
        while (t_start->next) {
            if (t_start->next->data->pid == current->pid){
                th = t_start->next;
                t_start->next = t_start->next->next;
                break;
            }
            t_start = t_start->next;
        }
    }
    if(th)
        kfree(th);
    return 0;
}


int memory_container_create(struct memory_container_cmd __user *user_cmd)
{
    //printk("---- CREATE ----\n");
    struct memory_container_cmd temp;
    copy_from_user(&temp, user_cmd, sizeof(struct memory_container_cmd));
    __u64 cid = temp.cid;

    //printk("CID - %llu\n", cid);
    if (!container){
        container = kcalloc(1, sizeof(struct Container), GFP_KERNEL);
        container->cid = cid;
        container->next = NULL;
        container->thread = NULL;
        container->object = NULL;
        mutex_init(&(container->container_lock));
    }
    
    bool found = false;
    struct Container *start = container;

    do{
        if (start->cid == cid){
            found = true;
            break;
        }
        if (!(start->next)){
            break;
        }
        start = start->next;
    }while(start);
    
    if (!found && container->cid != cid){
        //printk("CONTAINER NOT FOUND\n");
        struct Container *new_container = kcalloc(1, sizeof(struct Container), GFP_KERNEL);
        new_container->cid = cid;
        new_container->next = NULL;
        new_container->thread = NULL;
        new_container->object = NULL;
        start->next = new_container;
        start = start->next;
        mutex_init(&(start->container_lock));
    }
    
    struct Thread *t_start = start->thread;
    struct Thread *new_thread = kcalloc(1, sizeof(struct Thread), GFP_KERNEL);
    new_thread->data = current;
    new_thread->next = NULL;

    if (!start->thread){
        start->thread = new_thread;
    } else {
        while (t_start->next){
            t_start = t_start->next;
        }
        t_start->next = new_thread;
    }
    //print_ds();
    return 0;
}

int memory_container_free(struct memory_container_cmd __user *user_cmd)
{
    //printk("---- FREE ----\n");
    struct memory_container_cmd temp;
    copy_from_user(&temp, user_cmd, sizeof(struct memory_container_cmd));
    
    struct Container* container = get_container();
    struct Object* obj = get_object(container, temp.oid);
    kfree(obj->address);
    obj->address = NULL;

    if (container->object->oid == temp.oid) {
        container->object = container->object->next;
    } else {
        struct Object *t_obj = container->object;
        while (t_obj->next) {
            if (t_obj->next->oid == temp.oid){
                t_obj->next = t_obj->next->next;
                break;
            }
            t_obj = t_obj->next;
        }
    }
    kfree(obj);
    return 0;
}


/**
 * control function that receive the command in user space and pass arguments to
 * corresponding functions.
 */
int memory_container_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    switch (cmd)
    {
    case MCONTAINER_IOCTL_CREATE:
        return memory_container_create((void __user *)arg);
    case MCONTAINER_IOCTL_DELETE:
        return memory_container_delete((void __user *)arg);
    case MCONTAINER_IOCTL_LOCK:
        return memory_container_lock((void __user *)arg);
    case MCONTAINER_IOCTL_UNLOCK:
        return memory_container_unlock((void __user *)arg);
    case MCONTAINER_IOCTL_FREE:
        return memory_container_free((void __user *)arg);
    default:
        return -ENOTTY;
    }
}
