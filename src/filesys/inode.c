#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_BLOCK_CNT 123
#define INDIRECT_BLOCK_CNT 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t isdir;
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t to[DIRECT_BLOCK_CNT];
    block_sector_t indirect, doubly_indirect;
    // 125 * 4 + 3 * 4 = 512;
  };

struct indirect_inode_disk
  {
    block_sector_t to[INDIRECT_BLOCK_CNT];
  };

char zeros[BLOCK_SECTOR_SIZE];

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

// inode should be a top-level disk_inode
// GET
// SET
// GET THEN SET
static bool
get_set_sector (struct inode_disk *idisk, int sec, int l, block_sector_t *get_to, block_sector_t *set_from)
{
  if (l < DIRECT_BLOCK_CNT)
  {
    if (get_to)
    {
      *get_to = idisk->to[l];
    }
    if (set_from)
    {
      idisk->to[l] = *set_from;
      cache_write (sec, idisk);
    }
    return true;
  }

  l -= DIRECT_BLOCK_CNT;
  if (l < INDIRECT_BLOCK_CNT)
  {
    // single indirect
    struct indirect_inode_disk indirect;

    if (!idisk->indirect)
      if (set_from) {
        free_map_allocate (1, &idisk->indirect);
        cache_write (idisk->indirect, zeros);
        cache_write (sec, idisk);
      } else return false;

    cache_read (idisk->indirect, &indirect);
    
    if (get_to)
    {
      *get_to = indirect.to[l];
    }
    if (set_from)
    {
      indirect.to[l] = *set_from;
      cache_write (idisk->indirect, &indirect);
    }
    return true;
  }
    
  l -= INDIRECT_BLOCK_CNT;
  if (l < INDIRECT_BLOCK_CNT * INDIRECT_BLOCK_CNT)
  {
    // double indirect
    struct indirect_inode_disk id1, id2;

    if (!idisk->doubly_indirect)
      if (set_from) {
        free_map_allocate (1, &idisk->doubly_indirect);
        cache_write (idisk->doubly_indirect, zeros);
        cache_write (sec, idisk);
      } else return false;

    cache_read (idisk->doubly_indirect, &id1);

    if (!id1.to[l / INDIRECT_BLOCK_CNT])
      if (set_from) {
        free_map_allocate (1, &id1.to[l / INDIRECT_BLOCK_CNT]);
        cache_write (id1.to[l / INDIRECT_BLOCK_CNT], zeros);
        cache_write (idisk->doubly_indirect, &id1);
      } else return false;

    cache_read (id1.to[l / INDIRECT_BLOCK_CNT], &id2);

    if (get_to)
    {
      *get_to = id2.to[l % INDIRECT_BLOCK_CNT];
    }
    if (set_from)
    {
      id2.to[l % INDIRECT_BLOCK_CNT] = *set_from;
      cache_write (id1.to[l / INDIRECT_BLOCK_CNT], &id2);
    }
    return true;
  }
  return false;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
  {
    int l = pos / BLOCK_SECTOR_SIZE, ret = 23333333;
    get_set_sector (&inode->data, inode->sector, l, &ret, NULL);
    return ret;
  }
  return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

bool inode_extend (struct inode_disk *idisk, block_sector_t sec, off_t t_sec)
{
  size_t f_sec = bytes_to_sectors (idisk->length);
  block_sector_t nnode;
  if (f_sec >= t_sec)
    return true;

  for (int i = f_sec; i < t_sec; ++i)
  {
    if (!free_map_allocate (1, &nnode))
      return false;
    cache_write (nnode, zeros);
    if (!get_set_sector (idisk, sec, i, NULL, &nnode)) 
      return false;
  }
  return true;
}

bool inode_trunc (struct inode_disk *idisk, block_sector_t sec, off_t t_sec)
{
  size_t f_sec = bytes_to_sectors (idisk->length);
  block_sector_t nnode, set_from = 0;
  if (f_sec <= t_sec)
    return true;
  for (int i = t_sec; i < f_sec; ++i)
  {
    if (!get_set_sector (idisk, sec, i, &nnode, &set_from))
      return false;
    free_map_release (nnode, 1);
  } 
  if (f_sec >= DIRECT_BLOCK_CNT && t_sec < DIRECT_BLOCK_CNT)
    free_map_release (idisk->indirect, 1);
  if (f_sec >= DIRECT_BLOCK_CNT + INDIRECT_BLOCK_CNT && t_sec < DIRECT_BLOCK_CNT + INDIRECT_BLOCK_CNT)
    free_map_release (idisk->doubly_indirect, 1);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool isdir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->isdir = isdir;
      disk_inode->magic = INODE_MAGIC;
      
      if (inode_extend (disk_inode, sector, sectors)) 
        {
          disk_inode->length = length;
          cache_write (sector, disk_inode);
          success = true; 
        } 
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read (inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

bool 
inode_is_dir (const struct inode* inode) 
{
  return inode->data.isdir;
}

/* Returns INODE's inode number. */
int
inode_get_sector (const struct inode* inode) 
{
  return inode->sector;
}

bool
inode_removed (const struct inode* inode)
{
  return inode->removed;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          inode_trunc (&inode->data, inode->sector, 0);
          free_map_release (inode->sector, 1);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_read (sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  if (inode_extend (&inode->data, inode->sector, bytes_to_sectors(offset + size - 1)))
  {
    if (offset + size > inode->data.length)
    {
      inode->data.length = offset + size;
      cache_write (inode->sector, &inode->data);
    }  
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      if (sector_idx < 0)
      {
        break;
      }

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            cache_read (sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write (sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
