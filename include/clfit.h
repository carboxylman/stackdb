#ifndef __CLFIT_H__
#define __CLFIT_H__

#include <Judy.h>
#include "alist.h"

typedef Pvoid_t clrange_t;

clrange_t clrange_create();
int clrange_add(clrange_t *clf,Word_t start,Word_t end,void *data);
void *clrange_find(clrange_t *clf,Word_t index);
void clrange_free(clrange_t *clf);

typedef Pvoid_t clmatch_t;

clmatch_t clmatch_create();
int clmatch_add(clmatch_t *clf,Word_t index,void *data);
struct array_list *clmatch_find(clmatch_t *clf,Word_t index);
void clmatch_free(clmatch_t *clf);

/*
//Insert interval
int itvins( void **judy, Word_t begin, Word_t end ) {
    void *pval = JudyLIns(judy, begin, NULL); if(!pval) return -1;
   *pval = end;
   return 0;
}

//Search Interval
Word_t itvget( void *judy, Word_t *begin) { 
   Word_t val = *begin;
   void *pval = JudyLPrev(judy,  begin, NULL) ;
   if(pval && val >= begin && val <= *pval) return *pval;
   return -1;
}

main()
{
  void *judy = NULL;
   itvins(&judy, 0,8); 
   itvins(&judy, 16,24);
   // ...
   // search for any point in range (4,20)
  Word_t begin=4, end;
   if((end = itvget(judy, &begin)) == -1) itvins(&judy, 4,20);
}

.....et voila!


http://judy.sourceforge.net/doc/JudyL_3x.htm

http://article.gmane.org/gmane.comp.lib.judy.devel/328

*/

#endif

