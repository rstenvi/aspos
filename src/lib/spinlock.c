/**
* Spinlock which is used as a mutex to safeguard multiple CPU cores from using the
* same variables simultaneously.
*/

#include "lib.h"

/**
* Perform a spinlock to acquire a lock. Release with :c:func:`mutex_release`
*
* There is no fallback on this, so if the resource is not released, this will
* cause an endless loop.
*
* Parameters:
*	lock: Pointer to an 8-bit value which acts as the lock.
*
* Returns
*	:c:type:`OK`
*/
int mutex_acquire(volatile uint8_t* lock)	{
	/*
	* Description of function froom GCC website:
	* "This built-in function performs an atomic test-and-set operation on the
	* byte at *ptr. The byte is set to some implementation defined nonzero 'set'
	* value and the return value is true if and only if the previous contents
	* were 'set'. It should be only used for operands of type bool or char. For
	* other types only part of the value may be set."
	*/
	while(__atomic_test_and_set(lock, __ATOMIC_RELAXED) == true)	{

	}
	return OK;
}

/**
* Try and acquire the lock.
*
* Params:
*	lock: Pointer to an 8-bit value which acts as the lock.
* Returns:
*	:c:type:`OK` on success and :c:type:`GENERAL_FAULT` on failure.
*/
int mutex_try_acquire(volatile uint8_t* lock)	{
	if(__atomic_test_and_set(lock, __ATOMIC_RELAXED) == true)
		return -(GENERAL_FAULT);

	return OK;
}

/**
* Release a lock that has previously been held by :c:func:`mutex_acquire`.
*
* Params:
*	lock: Pointer to an 8-bit value which acts as the lock.
* Returns:
*	:c:type:`OK`
*/
int mutex_release(volatile uint8_t* lock)	{
	__atomic_clear(lock, __ATOMIC_RELAXED);
	return OK;
}

/**
* Intialize the lock to unlocked.
* Params:
*	lock: Pointer to an 8-bit value which acts as the lock.
* Returns:
*	:c:type:`OK`
*/
int mutex_clear(volatile uint8_t* lock)	{
	__atomic_clear(lock, __ATOMIC_RELAXED);
	return OK;
}
