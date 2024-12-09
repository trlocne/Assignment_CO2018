//#ifdef MM_PAGING
/*
 * PAGING based Memory Management
 * Virtual memory module mm/mm-vm.c
 */

#include "string.h"
#include "mm.h"
#include <stdlib.h>
#include <stdio.h>
//include thêm
#include <pthread.h>
static pthread_mutex_t mmvm_lock = PTHREAD_MUTEX_INITIALIZER;

/*enlist_vm_freerg_list - add new rg to freerg_list
 *@mm: memory region
 *@rg_elmt: new region
 *
 */
int enlist_vm_freerg_list(struct mm_struct *mm, struct vm_rg_struct* rg_elmt)
{  
    struct vm_rg_struct* rg_new_node = malloc(sizeof(struct vm_rg_struct));
    if (!rg_new_node) {        
      return -1;
    }

    struct vm_area_struct* cur_vma = get_vma_by_num(mm, rg_elmt->vmaid);
    if (!cur_vma) {        
      free(rg_new_node);
      return -1;
    }

    int vmaid = rg_elmt->vmaid;
    int lower_bound = rg_elmt->rg_start;
    int upper_bound = rg_elmt->rg_end;
    int temp_lower_bound = (vmaid) ? (lower_bound + 1) : (lower_bound - 1);
    int temp_upper_bound = (vmaid) ? (upper_bound - 1) : (upper_bound + 1);    

    // // Kiểm tra giá trị hợp lệ
    if(lower_bound >= upper_bound && rg_elmt->vmaid == 0) {
      free(rg_new_node);
      return -1;
    }
    if(lower_bound <= upper_bound && rg_elmt->vmaid == 1) {
      free(rg_new_node);
      return -1;
    }
  
    // Cập nhật thông tin vùng mới
    rg_new_node->rg_start = lower_bound;
    rg_new_node->rg_end = upper_bound;
    rg_new_node->rg_next = NULL;

    struct vm_rg_struct* prev = NULL;  

    // Trường hợp danh sách trống hoặc vùng mới nằm trước tất cả
    if(vmaid){
      if (!cur_vma->vm_freerg_list || cur_vma->vm_freerg_list->rg_start <= upper_bound) {
        rg_new_node->rg_next = cur_vma->vm_freerg_list;
        cur_vma->vm_freerg_list = rg_new_node;
      } else {
          // Duyệt danh sách để tìm vị trí phù hợp
          prev = cur_vma->vm_freerg_list;
          while (prev->rg_next && prev->rg_next->rg_start > upper_bound) {
              prev = prev->rg_next;
          }
          rg_new_node->rg_next = prev->rg_next;
          prev->rg_next = rg_new_node;
      }            

    }else{
      if (!cur_vma->vm_freerg_list || cur_vma->vm_freerg_list->rg_start >= upper_bound) {
        rg_new_node->rg_next = cur_vma->vm_freerg_list;
        cur_vma->vm_freerg_list = rg_new_node;
      } else {
          // Duyệt danh sách để tìm vị trí phù hợp
          prev = cur_vma->vm_freerg_list;
          while (prev->rg_next && prev->rg_next->rg_start < upper_bound) {
              prev = prev->rg_next;
          }
          rg_new_node->rg_next = prev->rg_next;
          prev->rg_next = rg_new_node;
      }        
      
    }    

    // Merge với vùng liền kề phía trước (nếu có)
    if (prev && prev->rg_end == temp_lower_bound) {
      prev->rg_end = upper_bound;
      prev->rg_next = rg_new_node->rg_next;
      free(rg_new_node);
    }    
    
    // Merge với vùng liền kề phía sau (nếu có)
    struct vm_rg_struct *deleted = prev->rg_next; 
    if (prev->rg_next && temp_upper_bound == prev->rg_next->rg_start) {
      prev->rg_end = prev->rg_next->rg_end;
      prev->rg_next = deleted->rg_next;
      free(deleted);      
    }
    return 0;
}

/*get_vma_by_num - get vm area by numID
 *@mm: memory region
 *@vmaid: ID vm area to alloc memory region
 *
 */
struct vm_area_struct *get_vma_by_num(struct mm_struct *mm, int vmaid)
{
  struct vm_area_struct *pvma= mm->mmap;

  if(mm->mmap == NULL)
    return NULL;

  int vmait = 0;
  
  while (vmait < vmaid)
  {
    if(pvma == NULL)
	  return NULL;

    vmait++;
    pvma = pvma->vm_next;
  }

  return pvma;
}

/*get_symrg_byid - get mem region by region ID
 *@mm: memory region
 *@rgid: region ID act as symbol index of variable
 *
 */
struct vm_rg_struct *get_symrg_byid(struct mm_struct *mm, int rgid)
{
  if(rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ)
    return NULL;

  if(mm->symrgtbl[rgid].rg_start == -1 || mm->symrgtbl[rgid].rg_end == -1){
    printf("\tACCESS FREE REGION\n");
    return NULL;
  }

  return &mm->symrgtbl[rgid];
}

/*__alloc - allocate a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size 
 *@alloc_addr: address of allocated memory region
 *
 */
int __alloc(struct pcb_t *caller, int vmaid, int rgid, int size, int *alloc_addr)
{
  /*Allocate at the toproof */
  struct vm_rg_struct rgnode;

  /* TODO: commit the vmaid */
  // rgnode.vmaid

  if (get_free_vmrg_area(caller, vmaid, size, &rgnode) == 0)
  {        
    caller->mm->symrgtbl[rgid].rg_start = rgnode.rg_start;
    caller->mm->symrgtbl[rgid].rg_end = rgnode.rg_end;

    caller->mm->symrgtbl[rgid].vmaid = vmaid;

    *alloc_addr = rgnode.rg_start;    

    return 0;
  }      
  

  pthread_mutex_init(&mmvm_lock,NULL);
  /* TODO: get_free_vmrg_area FAILED handle the region management (Fig.6)*/


  /* TODO retrive current vma if needed, current comment out due to compiler redundant warning*/
  /*Attempt to increate limit to get space */
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  // int inc_sz = PAGING_PAGE_ALIGNSZ(size); // số lượng page cần -> làm tròn lên
  //struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  
  int inc_limit_ret;

  /* TODO retrive old_sbrk if needed, current comment out due to compiler redundant warning*/
  int old_sbrk = cur_vma->sbrk;  

  /* TODO INCREASE THE LIMIT
   * inc_vma_limit(caller, vmaid, inc_sz)
   */
  // inc_vma_limit(caller, vmaid, inc_sz, &inc_limit_ret);

  /* TODO: commit the limit increment */
  pthread_mutex_lock(&mmvm_lock);
  if(abs(cur_vma->vm_end - cur_vma->sbrk) < size){
    if(inc_vma_limit(caller, vmaid, size, &inc_limit_ret) != 0){
      pthread_mutex_unlock(&mmvm_lock);      
      return -1;
    }
  }
  pthread_mutex_unlock(&mmvm_lock);

  /*Successful increase limit */  
  if(vmaid == 0){
    caller->mm->symrgtbl[rgid].rg_start = old_sbrk;
    caller->mm->symrgtbl[rgid].rg_end = old_sbrk + size - 1;
    caller->mm->symrgtbl[rgid].vmaid = vmaid;    
    cur_vma->sbrk += size;    

  }
  else{
    caller->mm->symrgtbl[rgid].rg_start = old_sbrk;
    caller->mm->symrgtbl[rgid].rg_end = old_sbrk - size + 1;
    caller->mm->symrgtbl[rgid].vmaid = vmaid;    
    cur_vma->sbrk -= size;    
  }

  printf("\tregister: %d; start: %ld; end: %ld\n", rgid, caller->mm->symrgtbl[rgid].rg_start, caller->mm->symrgtbl[rgid].rg_end);
  

  // collect the remain region
  // for debug  
  

  /* TODO: commit the allocation address 
  // *alloc_addr = ...
  */

  *alloc_addr = old_sbrk;

  // for debug  
  print_pgtbl(caller, 0, -1);
  return 0;
}

/*__free - remove a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size 
 *
 */
int __free(struct pcb_t *caller, int rgid)
{
  pthread_mutex_lock(&mmvm_lock);
  struct vm_rg_struct* rgnode;
  // Dummy initialization for avoding compiler dummay warning
  // in incompleted TODO code rgnode will overwrite through implementing
  // the manipulation of rgid later
  // rgnode.vmaid = 0;  //dummy initialization
  // rgnode.vmaid = 1;  //dummy initialization 

  if(rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ){        
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }  
  /* TODO: Manage the collect freed region to freerg_list */
  // check double free
  rgnode = &(caller->mm->symrgtbl[rgid]);    
  if (rgnode->rg_start == -1 && rgnode->rg_end == -1)
  {  
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }

  /*enlist the obsoleted memory region */
  enlist_vm_freerg_list(caller->mm, rgnode);  // clone node lại
  rgnode->rg_start = -1;
  rgnode->rg_end = -1;
  rgnode->rg_next = NULL;
  pthread_mutex_unlock(&mmvm_lock);

  print_pgtbl(caller, 0, -1);

  return 0;
}

/*pgalloc - PAGING-based allocate a region memory
 *@proc:  Process executing the instruction
 *@size: allocated size 
 *@reg_index: memory region ID (used to identify variable in symbole table)
 */
int pgalloc(struct pcb_t *proc, uint32_t size, uint32_t reg_index)
{
  int addr;    
  /* By default using vmaid = 0 */
  return __alloc(proc, 0, reg_index, size, &addr);
}

/*pgmalloc - PAGING-based allocate a region memory
 *@proc:  Process executing the instruction
 *@size: allocated size 
 *@reg_index: memory region ID (used to identify vaiable in symbole table)
 */
int pgmalloc(struct pcb_t *proc, uint32_t size, uint32_t reg_index)
{
  int addr;
  /* By default using vmaid = 1 */
  return __alloc(proc, 1, reg_index, size, &addr);
}

/*pgfree - PAGING-based free a region memory
 *@proc: Process executing the instruction
 *@size: allocated size 
 *@reg_index: memory region ID (used to identify variable in symbole table)
 */

int pgfree_data(struct pcb_t *proc, uint32_t reg_index)
{
   return __free(proc, reg_index);
}

/*pg_getpage - get the page in ram
 *@mm: memory region
 *@pagenum: PGN
 *@framenum: return FPN
 *@caller: caller
 *
 */
int pg_getpage(struct mm_struct *mm, int pgn, int *fpn, struct pcb_t *caller)
{
  uint32_t pte = mm->pgd[pgn];      
  if (!PAGING_PTE_PAGE_PRESENT(pte))
  { /* Page is not online, make it actively living */  
    // check if it din't exit in swap    
    if(!PAGING_PTE_PAGE_SWAPPED(pte)) return -1;

    int vicpgn, swpfpn; 
    int vicfpn;
    uint32_t vicpte;

    // get page trong swap
    int tgtfpn = PAGING_PTE_SWP(pte);//the target frame storing our variable        

    /* TODO: Play with your paging theory here */
    /* Find victim page */        
    if(find_victim_page(caller->mm, &vicpgn) != 0) return -1;
    /* Find victim frame */    
    vicpte = caller->mm->pgd[vicpgn];    
    vicfpn = PAGING_PTE_FPN(vicpte);    

    /* Get free frame in MEMSWP */
    MEMPHY_get_freefp(caller->active_mswp, &swpfpn);


    /* Do swap frame from MEMRAM to MEMSWP and vice versa*/
    /* Copy victim frame to swap */
    __swap_cp_page(caller->mram, vicfpn, caller->active_mswp, swpfpn);
    /* Copy target frame from swap to mem */
    __swap_cp_page(caller->active_mswp, tgtfpn, caller->mram, vicfpn);

    /* Update page table */
    pte_set_swap(&mm->pgd[vicpgn], 0, swpfpn);

    /* Update its online status of the target page */
    //pte_set_fpn() & mm->pgd[pgn];
    pte_set_fpn(&pte, vicfpn);
    mm->pgd[pgn] = pte;

    enlist_pgn_node(&caller->mm->fifo_pgn,pgn);
  }

  *fpn = PAGING_PTE_FPN(pte); // get 13 bit last

  return 0;
}

/*pg_getval - read value at given offset
 *@mm: memory region
 *@addr: virtual address to acess 
 *@value: value
 *
 */
int pg_getval(struct mm_struct *mm, int addr, BYTE *data, struct pcb_t *caller, int vmaid)
{
  int pgn = PAGING_PGN(addr);
  int off = PAGING_OFFST(addr);
  // pgn = vmaid ? (pgn + 1) : pgn;
  off = vmaid ? (256 - off) : off;
  int fpn;

  /* Get the page to MEMRAM, swap from MEMSWAP if needed */
  if(pg_getpage(mm, pgn, &fpn, caller) != 0) 
    return -1; /* invalid page access */

  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;    
  
  MEMPHY_read(caller->mram,phyaddr, data);

  return 0;
}

/*pg_setval - write value to given offset
 *@mm: memory region
 *@addr: virtual address to acess 
 *@value: value
 *
 */
int pg_setval(struct mm_struct *mm, int addr, BYTE value, struct pcb_t *caller, int vmaid)
{  
  int pgn = PAGING_PGN(addr);
  int off = PAGING_OFFST(addr);
  
  // pgn = vmaid ? (pgn + 1) : pgn;
  off = vmaid ? (256 - off) : off;
  int fpn;
    
  
  /* Get the page to MEMRAM, swap from MEMSWAP if needed */
  if(pg_getpage(mm, pgn, &fpn, caller) != 0) {    
    return -1; /* invalid page access */
  }
    

  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;  
  // set dirty bit
  if(MEMPHY_write(caller->mram,phyaddr, value) == 0){
    // PAGING_PTE_SET_DIRTY(mm->pgd[pgn]);
  }

   return 0;
}

/*__read - read value in region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@offset: offset to acess in memory region 
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size 
 *
 */
int __read(struct pcb_t *caller, int rgid, int offset, BYTE *data)
{    
  struct vm_rg_struct *currg = get_symrg_byid(caller->mm, rgid);      
  if(currg == NULL){    
    return -1;
  }  
  int vmaid = currg->vmaid;
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  if(cur_vma == NULL) /* Invalid memory identify */
	  return -1;
  if(offset > abs(currg->rg_start - currg->rg_end)){
    printf("\tACCESS OUT OF REGION\n");
    return -1;
  } 
  if(currg->vmaid == 0){
    pg_getval(caller->mm, currg->rg_start + offset, data, caller, cur_vma->vm_id);
  }
  else{
    pg_getval(caller->mm, currg->rg_start - offset, data, caller, cur_vma->vm_id);
  }
  // pg_getval(caller->mm, currg->rg_start + offset, data, caller);
    


  return 0;
}


/*pgwrite - PAGING-based read a region memory */
int pgread(
		struct pcb_t * proc, // Process executing the instruction
		uint32_t source, // Index of source register
		uint32_t offset, // Source address = [source] + [offset]
		uint32_t destination) 
{
  BYTE data;
  int val = __read(proc, source, offset, &data);  
  
#ifdef IODUMP
  printf("\tread region=%d offset=%d value=%d\n", source, offset, data);
#ifdef PAGETBL_DUMP
  print_pgtbl(proc, 0, -1); //print max TBL
#endif
  MEMPHY_dump(proc->mram);
#endif  
  pgwrite(proc, data, destination, offset);

  return val;
}

/*__write - write a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@offset: offset to acess in memory region 
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size 
 *
 */
int __write(struct pcb_t *caller, int rgid, int offset, BYTE value)
{  
  struct vm_rg_struct *currg = get_symrg_byid(caller->mm, rgid);
  if(currg == NULL)
    return -1;

  int vmaid = currg->vmaid;

  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid); 
  if(offset > abs(currg->rg_start - currg->rg_end)){
    printf("\tACCESS OUT OF REGION\n");
    return -1;
  } 
  
  if(cur_vma == NULL) /* Invalid memory identify */
	  return -1;
  
  if(vmaid == 0){
    pg_setval(caller->mm, currg->rg_start + offset, value, caller, vmaid);
  }
  else{
    pg_setval(caller->mm, currg->rg_start - offset, value, caller, vmaid);
  }

  return 0;
}

/*pgwrite - PAGING-based write a region memory */
int pgwrite(
		struct pcb_t * proc, // Process executing the instruction
		BYTE data, // Data to be wrttien into memory
		uint32_t destination, // Index of destination register
		uint32_t offset)
{
  int val = __write(proc, destination, offset, data);
#ifdef IODUMP
  printf("\twrite region=%d offset=%d value=%d\n", destination, offset, data);
#ifdef PAGETBL_DUMP
  print_pgtbl(proc, 0, -1); //print max TBL
#endif
  MEMPHY_dump(proc->mram);
#endif
  return val;
}


/*free_pcb_memphy - collect all memphy of pcb
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@incpgnum: number of page
 */
int free_pcb_memph(struct pcb_t *caller)
{
  int pagenum, fpn;
  uint32_t pte;


  for(pagenum = 0; pagenum < PAGING_MAX_PGN; pagenum++)
  {
    pte= caller->mm->pgd[pagenum];

    if (!PAGING_PTE_PAGE_PRESENT(pte))
    {
      fpn = PAGING_PTE_FPN(pte);
      MEMPHY_put_freefp(caller->mram, fpn);
    } else {
      fpn = PAGING_PTE_SWP(pte);
      MEMPHY_put_freefp(caller->active_mswp, fpn);    
    }
  }

  return 0;
}

/*get_vm_area_node - get vm area for a number of pages
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@incpgnum: number of page
 *@vmastart: vma end
 *@vmaend: vma end
 *
 */
struct vm_rg_struct* get_vm_area_node_at_brk(struct pcb_t *caller, int vmaid, int size, int alignedsz)
{
  struct vm_rg_struct * newrg;
  /* TODO retrive current vma to obtain newrg, current comment out due to compiler redundant warning*/
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  newrg = malloc(sizeof(struct vm_rg_struct));

  /* TODO: update the newrg boundary  
  // newrg->rg_start = ...
  // newrg->rg_end = ...  
  */
 if(vmaid == 0){  
  newrg->vmaid = 0;
  newrg->rg_start = cur_vma->sbrk;
  newrg->rg_end = newrg->rg_start + size - 1;
 }
 else{
  // implement for heap segment  
  newrg->rg_start = cur_vma->sbrk;
  newrg->rg_end = newrg->rg_start - size + 1;
  newrg->vmaid = 1;
 }

  return newrg;
}

/*validate_overlap_vm_area
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@vmastart: vma end
 *@vmaend: vma end
 *
 */
int validate_overlap_vm_area(struct pcb_t *caller, int vmaid, int vmastart, int vmaend)
{
  struct vm_area_struct *vma = get_vma_by_num(caller->mm, vmaid);
  struct vm_area_struct *check_vma = get_vma_by_num(caller->mm, (vmaid)?0:1);
  unsigned char check = 0;
  if(vmaid){
    check = (vmaend - check_vma->vm_end) > 0 ? 0 : 1;
  }
  else{
    check = (vmaend - check_vma->vm_end) < 0 ? 0 : 1;
  }
  /* TODO validate the planned memory area is not overlapped */
  /* Nếu không phát hiện trùng lặp, trả về 0 */
  return OVERLAP(vmastart,vmaend,vma->vm_start,vma->vm_end) || check;
}

/*inc_vma_limit - increase vm area limits to reserve space for new variable
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@inc_sz: increment size 
 *@inc_limit_ret: increment limit return
 *
 */
int inc_vma_limit(struct pcb_t *caller, int vmaid, int inc_sz, int* inc_limit_ret)
{    
  struct vm_rg_struct * newrg = malloc(sizeof(struct vm_rg_struct));  
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  int dec_size = (vmaid) ? (cur_vma->sbrk - cur_vma->vm_end) : (cur_vma->vm_end - cur_vma->sbrk);
  int temp_size = (inc_sz - dec_size);
  int inc_amt = PAGING_PAGE_ALIGNSZ(temp_size);
  int incnumpage =  inc_amt / PAGING_PAGESZ;  
  struct vm_rg_struct *area = get_vm_area_node_at_brk(caller, vmaid, inc_sz, inc_amt);
  

  int old_end = cur_vma->vm_end;

  /*Validate overlap of obtained region */
  // if (validate_overlap_vm_area(caller, vmaid, area->rg_start, area->rg_end)){    
  //   return -1; /*Overlap and failed allocation */
  // }

  /* TODO: Obtain the new vm area based on vmaid */
  //cur_vma->vm_end... 
  // inc_limit_ret...
  if(vmaid == 0){
    cur_vma->vm_end += inc_amt;    
    newrg->vmaid = 0;
  }
  else{
    cur_vma->vm_end -= inc_amt;    
    newrg->vmaid = 1;
  }

  *inc_limit_ret = cur_vma->vm_end;

  if (vm_map_ram(caller, area->rg_start, area->rg_end, 
                    old_end, incnumpage , newrg) < 0){                      
                      return -1; /* Map the memory to MEMRAM */
                    }        
  return 0;
}

/*find_victim_page - find victim page
 *@caller: caller
 *@pgn: return page number
 *
 */
int find_victim_page(struct mm_struct *mm, int *retpgn) 
{
  struct pgn_t *pg = mm->fifo_pgn;  

  /* TODO: Implement the theorical mechanism to find the victim page */
  if(pg == NULL)
    return -1;
  struct pgn_t *prev = NULL;
  while (pg->pg_next) 
  {
    prev = pg;
    pg = pg->pg_next;
  }
  *retpgn = pg->pgn;
  if (prev)
    prev->pg_next = NULL; 
  else 
  {
    mm->fifo_pgn = NULL;
  }
  free(pg);  

  return 0;
}

/*get_free_vmrg_area - get a free vm region
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@size: allocated size 
 *
 */
int get_free_vmrg_area(struct pcb_t *caller, int vmaid, int size, struct vm_rg_struct *newrg)
{
  size -= 1;
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  if (cur_vma == NULL || cur_vma->vm_freerg_list == NULL)
    return -1;

  struct vm_rg_struct *rgit = cur_vma->vm_freerg_list;
  // print_list_rg(cur_vma->vm_freerg_list);
  /* Probe uninitialized newrg */
  newrg->rg_start = newrg->rg_end = -1;

  /* Traverse the list of free regions to find a fit space */
  while (rgit != NULL)
  {
    if (vmaid == 0) // Data region: allocate from low to high address
    {      
      if (rgit->rg_start + size <= rgit->rg_end)
      { 
        // Current region has enough space
        newrg->rg_start = rgit->rg_start;
        newrg->rg_end = rgit->rg_start + size;

        // Update left space in the chosen region
        if (rgit->rg_start + size < rgit->rg_end)
        {
          rgit->rg_start = rgit->rg_start + size;
        }
        else
        { 
          // Use up all space, remove current node
          struct vm_rg_struct *nextrg = rgit->rg_next;

          if (nextrg != NULL)
          {
            rgit->rg_start = nextrg->rg_start;
            rgit->rg_end = nextrg->rg_end;
            rgit->rg_next = nextrg->rg_next;
            

            free(nextrg);
          }
          else
          { 
            // End of free list
            rgit->rg_start = rgit->rg_end = 0;
            rgit->rg_next = NULL;
          }
        }
        break; // Region found, exit loop
      }
    }
    else if (vmaid == 1) // Heap region: allocate from high to low address
    {                   
      if (rgit->rg_end + size <= rgit->rg_start)
      {             
        // Current region has enough space
        newrg->rg_start = rgit->rg_start;
        newrg->rg_end = rgit->rg_start - size;

        // Update remaining space in the chosen region
        if (rgit->rg_start - size > rgit->rg_end)
        {
          rgit->rg_start = rgit->rg_start - size;
        }
        else
        {
          // Use up all space, remove current node
          struct vm_rg_struct *nextrg = rgit->rg_next;

          if (nextrg != NULL)
          {
            rgit->rg_start = nextrg->rg_start;
            rgit->rg_end = nextrg->rg_end;
            rgit->rg_next = nextrg->rg_next;
            
            free(nextrg);
          }
          else
          { 
            // End of free list
            rgit->rg_start = rgit->rg_end = caller->vmemsz;
            rgit->rg_next = NULL;
          }
        }
        break; // Region found, exit loop
      }
    }

    // Move to the next region in the free list
    rgit = rgit->rg_next;
    
  }

  // Check if a suitable region was found
  if (newrg->rg_start == -1)
    return -1;

  return 0;
}

//#endif
