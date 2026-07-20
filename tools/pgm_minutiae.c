/* Offline NBIS tuning harness: load a raw 8-bit PGM, wrap it in an FpImage
 * with a given ppmm, run fp_image_detect_minutiae, print the count.
 *
 * Usage: pgm-minutiae <image.pgm> [ppmm]
 *
 * Build (from the repository root):
 *   gcc tools/pgm_minutiae.c -o build/pgm-minutiae \
 *     $(pkg-config --cflags --libs glib-2.0 gio-2.0 gobject-2.0 gusb cairo) \
 *     -I libfprint -I libfprint/libfprint -I libfprint/build/libfprint \
 *     -L libfprint/build/libfprint -lfprint-2 -lssl -lcrypto -lpthread -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "libfprint/fpi-image.h"   /* struct _FpImage (internal) */
#include "libfprint/fp-image.h"

static FpImage *main_loop_image;
static GMainLoop *loop;
static int minutiae_count = -1;

static FpImage *
load_pgm (const char *path)
{
  FILE *f = fopen (path, "r");
  char magic[3] = {0};
  int width, height, maxval;

  if (!f)
    return NULL;
  if (fscanf (f, "%2s", magic) != 1 || strcmp (magic, "P5") != 0)
    {
      fclose (f);
      return NULL;
    }
  if (fscanf (f, "%d %d %d", &width, &height, &maxval) != 3)
    {
      fclose (f);
      return NULL;
    }
  fgetc (f); /* single whitespace after maxval */

  FpImage *img = fp_image_new (width, height);
  if (fread (img->data, 1, width * height, f) != (size_t) (width * height))
    {
      fclose (f);
      return NULL;
    }
  fclose (f);
  return img;
}

static void
on_detected (FpImage *image, GAsyncResult *res, gpointer user_data)
{
  GError *error = NULL;

  if (!fp_image_detect_minutiae_finish (image, res, &error))
    {
      fprintf (stderr, "detect failed: %s\n", error->message);
      g_main_loop_quit (loop);
      return;
    }
  GPtrArray *minutiae = fp_image_get_minutiae (image);
  minutiae_count = minutiae ? (int) minutiae->len : 0;

  const char *bin_out = g_object_get_data (G_OBJECT (image), "bin-out");
  if (bin_out && image->binarized)
    {
      FILE *f = fopen (bin_out, "w");
      fprintf (f, "P5\n%d %d\n255\n", image->width, image->height);
      for (int i = 0; i < image->width * image->height; i++)
        fputc (image->binarized[i] ? 255 : 0, f);
      fclose (f);
    }

  g_main_loop_quit (loop);
}

int
main (int argc, char **argv)
{
  if (argc < 2)
    {
      fprintf (stderr, "usage: %s <image.pgm> [ppmm]\n", argv[0]);
      return 2;
    }
  double ppmm = argc > 2 ? g_strtod (argv[2], NULL) : 500.0 / 25.4;

  FpImage *img = load_pgm (argv[1]);
  if (!img)
    {
      fprintf (stderr, "could not load %s (expecting binary P5 PGM)\n",
               argv[1]);
      return 2;
    }
  img->ppmm = ppmm;
  if (argc > 3)
    g_object_set_data (G_OBJECT (img), "bin-out", argv[3]);

  loop = g_main_loop_new (NULL, FALSE);
  fp_image_detect_minutiae (img, NULL, (GAsyncReadyCallback) on_detected,
                            NULL);
  g_main_loop_run (loop);

  printf ("ppmm=%.3f minutiae=%d\n", ppmm, minutiae_count);
  return minutiae_count >= 0 ? 0 : 1;
}
