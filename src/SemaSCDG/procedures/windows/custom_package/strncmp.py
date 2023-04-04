import angr

import logging
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS
from angr.storage.memory_mixins.regioned_memory.abstract_address_descriptor import AbstractAddressDescriptor


l = logging.getLogger("CustomSimProcedureWindows")

class strncmp(angr.SimProcedure):
    # pylint:disable=arguments-differ
    def strlen(self, s, wchar=False, maxlen=None):
        if wchar:
            null_seq = self.state.solver.BVV(0, 16)
            char_size = 2
        else:
            null_seq = self.state.solver.BVV(0, 8)
            char_size = 1

        max_symbolic_bytes = self.state.libc.buf_symbolic_bytes
        max_str_len = self.state.libc.max_str_len
        if maxlen:
            max_str_len = min(maxlen, max_str_len)

        chunk_size = None
        if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
            chunk_size = 1

        if self.state.mode == "static":

            max_null_index = 0

            # Make sure to convert s to ValueSet
            addr_desc: AbstractAddressDescriptor = self.state.memory._normalize_address(s)

            # size_t
            length = self.state.solver.ESI(self.arch.bits)
            for s_aw in self.state.memory._concretize_address_descriptor(addr_desc, None):

                s_ptr = s_aw.to_valueset(self.state)
                r, c, i = self.state.memory.find(
                    s,
                    null_seq,
                    max_str_len,
                    max_symbolic_bytes=max_symbolic_bytes,
                    chunk_size=chunk_size,
                    char_size=char_size,
                )

                max_null_index = max([max_null_index] + i)

                # Convert r to the same region as s
                r_desc = self.state.memory._normalize_address(r)
                r_aw_iter = self.state.memory._concretize_address_descriptor(
                    r_desc, None, target_region=next(iter(s_ptr._model_vsa.regions.keys()))
                )

                for r_aw in r_aw_iter:
                    r_ptr = r_aw.to_valueset(self.state)
                    length = length.union(r_ptr - s_ptr)

            return length, max_null_index

        else:
            search_len = max_str_len
            r, c, i = self.state.memory.find(
                s,
                null_seq,
                search_len,
                max_symbolic_bytes=max_symbolic_bytes,
                chunk_size=chunk_size,
                char_size=char_size,
            )

            # try doubling the search len and searching again
            s_new = s
            while c and all(con.is_false() for con in c):
                s_new += search_len
                search_len *= 2
                r, c, i = self.state.memory.find(
                    s_new,
                    null_seq,
                    search_len,
                    max_symbolic_bytes=max_symbolic_bytes,
                    chunk_size=chunk_size,
                    char_size=char_size,
                )
                # stop searching after some reasonable limit
                if search_len > 0x10000:
                    raise angr.SimMemoryLimitError("strlen hit limit of 0x10000")

            max_null_index = max(i)
            self.state.add_constraints(*c)
            result = r - s
            if result.depth > 3:
                rresult = self.state.solver.BVS("strlen", len(result), key=("api", "strlen"))
                self.state.add_constraints(result == rresult)
                result = rresult
            return result, max_null_index
 
    def run(
        self, a_addr, b_addr, limit, a_len=None, b_len=None, wchar=False, ignore_case=False
    ):  # pylint:disable=arguments-differ
        char_size = 1 if not wchar else 2
        print("ccoucou")
        a_strlen_ret_expr, a_strlen_max_null_index = self.strlen(a_addr,wchar=wchar)
        b_strlen_ret_expr, b_strlen_max_null_index = self.strlen(b_addr,wchar=wchar)
        print("swag")
        a_len = a_strlen_ret_expr
        b_len = b_strlen_ret_expr

        match_constraints = []
        variables = a_len.variables | b_len.variables | limit.variables
        ret_expr = self.state.solver.Unconstrained("strncmp_ret",  self.arch.bits, key=("api", "strncmp"))

        # determine the maximum number of bytes to compare
        concrete_run = False
        # if not self.state.solver.symbolic(a_len) and not self.state.solver.symbolic(b_len) and not self.state.solver.symbolic(limit):
        if (
            self.state.solver.single_valued(a_len)
            and self.state.solver.single_valued(b_len)
            and self.state.solver.single_valued(limit)
        ):
            c_a_len = self.state.solver.eval(a_len)
            c_b_len = self.state.solver.eval(b_len)
            c_limit = self.state.solver.eval(limit)

            l.info("everything is concrete: a_len %d, b_len %d, limit %d", c_a_len, c_b_len, c_limit)

            if (c_a_len < c_limit or c_b_len < c_limit) and c_a_len != c_b_len:
                l.info("lengths < limit and unmatched")

            concrete_run = True
            maxlen = min(c_a_len, c_b_len, c_limit)
        else:
            if self.state.solver.single_valued(limit):
                c_limit = self.state.solver.eval(limit)
                maxlen = min(a_strlen_max_null_index, b_strlen_max_null_index, c_limit)
            else:
                maxlen = max(a_strlen_max_null_index, b_strlen_max_null_index)

            match_constraints.append(
                self.state.solver.Or(
                    a_len == b_len,
                    self.state.solver.And(self.state.solver.UGE(a_len, limit), self.state.solver.UGE(b_len, limit)),
                )
            )

        if maxlen == 0:
            # there is a corner case: if a or b are not both empty string, and limit is greater than 0, we should return
            # non-equal. Basically we only return equal when limit is 0, or a_len == b_len == 0
            if self.state.solver.single_valued(limit) and self.state.solver.eval(limit) == 0:
                # limit is 0
                l.info("returning equal for 0-limit")
                return self.state.solver.BVV(0,  self.arch.bits)
            elif (
                self.state.solver.single_valued(a_len)
                and self.state.solver.single_valued(b_len)
                and self.state.solver.eval(a_len) == self.state.solver.eval(b_len) == 0
            ):
                # two empty strings
                l.info("returning equal for two empty strings")
                return self.state.solver.BVV(0,  self.arch.bits)
            else:
                # all other cases fall into this branch
                l.info("returning non-equal for comparison of an empty string and a non-empty string")
                if a_strlen_max_null_index == 0:
                    return self.state.solver.BVV(-1,  self.arch.bits)
                else:
                    return self.state.solver.BVV(1,  self.arch.bits)

        # the bytes
        max_byte_len = maxlen * char_size
        a_bytes = self.state.memory.load(a_addr, max_byte_len, endness="Iend_BE")
        b_bytes = self.state.memory.load(b_addr, max_byte_len, endness="Iend_BE")

        # TODO: deps

        # all possible return values in static mode
        return_values = []
        print("swag")
        print(max_byte_len)
        print(concrete_run)
        for i in range(max_byte_len):
            l.info("Processing byte %d", i)
            maxbit = (max_byte_len - i) * 8
            a_byte = a_bytes[maxbit - 1 : maxbit - 8]
            b_byte = b_bytes[maxbit - 1 : maxbit - 8]

            if concrete_run and self.state.solver.single_valued(a_byte) and self.state.solver.single_valued(b_byte):
                a_conc = self.state.solver.eval(a_byte)
                b_conc = self.state.solver.eval(b_byte)
                variables |= a_byte.variables
                variables |= b_byte.variables

                if ignore_case:
                    # convert both to lowercase
                    if ord("a") <= a_conc <= ord("z"):
                        a_conc -= ord(" ")
                    if ord("a") <= b_conc <= ord("z"):
                        b_conc -= ord(" ")

                if a_conc != b_conc:
                    l.info("... found mis-matching concrete bytes 0x%x and 0x%x", a_conc, b_conc)
                    if a_conc < b_conc:
                        return self.state.solver.BVV(-1,self.arch.bits)
                    else: # Not enough data for store
                        return self.state.solver.BVV(1, self.arch.bits)
            else:

                if self.state.mode == "static":
                    return_values.append(a_byte - b_byte)

                concrete_run = False

            if self.state.mode != "static":
                if ignore_case:
                    byte_constraint = self.state.solver.Or(
                        self.state.solver.Or(
                            a_byte == b_byte,
                            self.state.solver.And(
                                ord("A") <= a_byte,
                                a_byte <= ord("Z"),
                                ord("a") <= b_byte,
                                b_byte <= ord("z"),
                                b_byte - ord(" ") == a_byte,
                            ),
                            self.state.solver.And(
                                ord("A") <= b_byte,
                                b_byte <= ord("Z"),
                                ord("a") <= a_byte,
                                a_byte <= ord("z"),
                                a_byte - ord(" ") == b_byte,
                            ),
                        ),
                        self.state.solver.ULT(a_len, i),
                        self.state.solver.ULT(limit, i),
                    )
                else:
                    byte_constraint = self.state.solver.Or(
                        a_byte == b_byte, self.state.solver.ULT(a_len, i), self.state.solver.ULT(limit, i)
                    )
                match_constraints.append(byte_constraint)

        if concrete_run:
            l.info("concrete run made it to the end!")
            return self.state.solver.BVV(0,  self.arch.bits)

        if self.state.mode == "static":
            ret_expr = self.state.solver.ESI(8)
            for expr in return_values:
                ret_expr = ret_expr.union(expr)

            ret_expr = ret_expr.sign_extend(24)

        else:
            # make the constraints

            l.info("returning symbolic")
            match_constraint = self.state.solver.And(*match_constraints)
            nomatch_constraint = self.state.solver.Not(match_constraint)

            # l.info("match constraints: %s", match_constraint)
            # l.info("nomatch constraints: %s", nomatch_constraint)

            match_case = self.state.solver.And(limit != 0, match_constraint, ret_expr == 0)
            nomatch_case = self.state.solver.And(limit != 0, nomatch_constraint, ret_expr == 1)
            l0_case = self.state.solver.And(limit == 0, ret_expr == 0)
            empty_case = self.state.solver.And(a_strlen_ret_expr == 0, b_strlen_ret_expr == 0, ret_expr == 0)

            self.state.add_constraints(self.state.solver.Or(match_case, nomatch_case, l0_case, empty_case))

        return ret_expr