#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/synch.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();
  cache_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  cache_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool isdir) 
{
  char *path;
  char *filename;

  split(name, &path, &filename);

  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_path (path);
  
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, isdir)
                  && dir_add (dir, filename, inode_sector, isdir));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);
  
  free(path);
  free(filename);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  if (name[0] == '\0')
    return NULL;

  char *path;
  char *filename;

  split(name, &path, &filename);
  struct dir *dir = dir_open_path (path);
  struct inode *inode = NULL;

  if (dir == NULL)
    return NULL;
  
  if (filename[0] == '\0') {
    inode = dir->inode;
  } else {
    dir_lookup (dir, filename, &inode);
    dir_close (dir);
  } 
  
  free (path);
  free (filename);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir = dir_open_root ();
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir); 

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

void
split(const char* path, char** dir, char** filename) 
{
  int length = strlen(path);

  int split_pos = length-1;
  for ( ; split_pos >= 0; split_pos--)
    if (path[split_pos] == '/') break;
  
  int dir_length = split_pos + 1;
  int filename_length = length - split_pos - 1;
  
  *dir = malloc (dir_length + 1);
  *filename = malloc (filename_length + 1);
  
  memcpy (*dir, path, dir_length);
  memcpy (*filename, path + dir_length, filename_length);

  (*dir)[dir_length] = '\0';
  (*filename)[filename_length] = '\0';
}