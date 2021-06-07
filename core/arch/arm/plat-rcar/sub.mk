global-incdirs-y += .
srcs-y += main.c
srcs-y += core_pos_a64.S
srcs-y += romapi.c
srcs-y += romapi_call.S
srcs-y += hw_rng.c
srcs-y += rcar_rproc.c

ifeq ($(CFG_RPROC_PTA),y)
gensrcs-y += rproc_pub_key
produce-rproc_pub_key = rproc_pub_key.c
depends-rproc_pub_key = $(CFG_RPROC_SIGN_KEY) scripts/pem_to_pub_c.py
recipe-rproc_pub_key = $(PYTHON3) scripts/pem_to_pub_c.py --prefix rproc_pub_key \
        --key $(CFG_RPROC_SIGN_KEY) --out $(sub-dir-out)/rproc_pub_key.c
endif
