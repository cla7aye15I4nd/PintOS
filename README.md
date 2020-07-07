# Pintos 2020
## Project 1: Threads
- Handle the sleep action by checking all threads when interrupt happened.
- Priority Schedule: Fetch the max priority thread by scanning all threads.
- Execute thread preempt when create thread and priority changed.
- Priority Donate:
  - Holder's priority should bigger than the waiter's priority
  - Save the max priority of all waiters in struct_lock as max_priority
  - Every thread save the max max_priority of all hold lock.
  - Update information at lock changed.
- Follow the tutorial to implement dynamic priority.

## Project 2: User Programs
- Get and pass arguments with the stack pointer.
- Check the address carefully, not just the starting address.
- Handle the syscalls with the base filesystem.
- The most tricky part is the process wait and the return status.
- Use semaphores to assure the values pass correctly.

## Project 3: Virtual Memory
- Frame Table
  - Maintain a hash table that translates a page to a frame. 
  - Allocate frames from the user pool if available.
  - When a frame replacement is necessary, use clock algorithm to evict frames efficiently.
  - Well designed lock mechanism, only lock when necessary.
- Supplemental Page Table
  - Maintains a hash table from virtual address to physical address.
  - Records whether the corresponding address is on the physical memory / swap / file.
  - Perfectly designed lock mechanism, only lock when necessary.
  - Able to handle page fault and grows the stack if deemed necessary.
  - Used for checking if a virtual address resides in the user address space and if it's a valid address.
- Swap Table
  - Uses BLOCK_SWAP block device. 
  - Utilizes bitmap for fast lookup of currently available slots.
- Memory Mapped Files
  - Maps files onto memory addresses by maintaining a mmap list in each process.
  - Works together with supplemental page table. Mmap list provides a translation from file to virtual address while supplemental page table translates it to the physical address.

## Project 4: File Systems
- Cache : Clock algorithm
- Extensible Files.
  - Use a doubly indirect inode to support a maximum 8MB file.
  - Well designed get_set function to handle byte to sector.
  - Well designed file_extend to support writing extra bytes and file allocation elegantly.
- Subdirectory : Save the parent directory in first file. (unavailable in root '/')