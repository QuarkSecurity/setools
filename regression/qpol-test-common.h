#include "policy-io.h"

/**
 *  Open a Binary Policy
 *
 * @param pol_path The full path to the binary policy file
 * @param p Reference to a binary policy structure
 * The caller must free the binary policy structure afterwards
 * @param num_results Reference to number of results, or 0 upon no
 * results or error.
 *
 * @return 0 on success, negative on error.
 */
int bin_open_policy(char *pol_path, apol_policy_t ** p);
