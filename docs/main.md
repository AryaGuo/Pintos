# Documents for Pintos

## Contributors

* Wenxuan Guo
    * wrote the code for threads
    * wrote the code for syscall related to process management
    * wrote the code for vm
    * helped with debugging
* Yulin Wang
    * wrote the code for syscall related to file system
    * wrote the code for vm
    * helped with debugging
* Yuhuan Yang: 
    * wrote the code for threads
    * wrote the code for syscall related to process management
    * helped with git, cmake and other tools
    * helped with debugging
* Qingyao Xu: 
    * wrote the code for syscall related to file system
    * helped with debugging

## Time Distribution
* threads: 2 days
* userprog: 4 days
* vm: 5 days

## Our Design

### Virtual Memory

* implement lazy-loading
* two global tables
    * swap table: keep the information of swap disk
    * frame table: keep the information of used frames
* two tables for each process
    * supplemental page table: record additional information of pages, such as dirty bits, necessary status for file loading
    * mmap table: keep track of all mmap-ed files and according pages

## Difficulties

* priority donation
* multi-thread debugging
* process management
* synchronization