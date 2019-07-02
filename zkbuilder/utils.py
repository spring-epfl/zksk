from collections import defaultdict


def check_groups(list_of_secret_vars, list_of_generators):
    """
    Check that if two secrets in the proof are the same, the generators at corresponding indices induce groups of same order.
    Can be deactivated in the future since it can forbid using different groups in one proof.

    The primary goal is to ensure same responses for same secrets will not yield false negatives of check_responses_consistency due to
    different group order modular reductions.

    :param list_of_secret_vars: a list of secrets names of type Secret.
    :param list_of_generators: a list of generators (bases).
    """
    # We map the unique secrets to the indices where they appear
    mydict = defaultdict(list)
    for idx, word in enumerate(list_of_secret_vars):
        mydict[word].append(idx)

    # Now we use this dictionary to check all the generators related to a particular secret live in the same group
    for (word, gen_idx) in mydict.items():
        # word is the key, gen_idx is the value = a list of indices
        ref_order = list_of_generators[gen_idx[0]].group.order()

        for index in gen_idx:
            if list_of_generators[index].group.order() != ref_order:
                raise Exception(
                    "A shared secret has generators which yield different group orders : secret",
                    word,
                )

    return True


