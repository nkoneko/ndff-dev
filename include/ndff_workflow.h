#ifndef _NDFF_WOWRKFLOW_H_
#define _NDFF_WOWRKFLOW_H_

typedef struct workflow {
    u_int64_t last_time;
    struct workflow_prefs prefs;
} workflow_t;

struct workflow *ndff_workflow_init();

#endif /* _NDFF_WORKFLOW_H */
