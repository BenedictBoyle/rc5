This is a toy implementation of RC5 I wrote to learn some basic crypto and C programming at the same time. 

It supports user-selected parameters for word length (16, 32 or 64-bit), secret key, encryption mode (ECB or CBC) and padding mode (PKCS7-style or Cipertext Stealing mode). 

It should be architecture agnostic, providing the C standard library is available, but I've only tested it on x64.

It has not been subject to any sort of assurance process, so the standard warning against using homespun crytography for protection of sensitive data applies.  
