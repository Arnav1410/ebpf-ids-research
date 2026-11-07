#ifndef TEST_ENV_NN_CONTEXT_H
#define TEST_ENV_NN_CONTEXT_H

struct nn_context_abi {
	unsigned int size;
	unsigned int cb_offset;
};

struct nn_context_abi nn_kernel_context_abi(void);

#endif
