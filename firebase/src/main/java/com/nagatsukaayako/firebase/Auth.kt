package com.nagatsukaayako.firebase

import android.app.Activity
import com.google.firebase.FirebaseException
import com.google.firebase.auth.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class ServerAuth private constructor() {
    class WrongCodeException : Exception("WrongCode")
    companion object {
        /**
         * check user is signed with firebase
         */
        val isUserSigned
            get() = FirebaseAuth.getInstance().currentUser != null

        val isBioSetted
            get() = FirebaseAuth.getInstance().currentUser?.displayName != null

        /**
         * @param number phone number of user
         * @throws FirebaseException
         */
        suspend fun verifyPhoneNumberAsync(number: String, activity: Activity) = suspendCancellableCoroutine<Unit> { continuation ->
            if (!instance.mutex.isLocked) {
                GlobalScope.launch {
                    instance.currentContinuation = continuation
                    instance.mutex.lock()
                    PhoneAuthProvider.getInstance().verifyPhoneNumber(number, 60, TimeUnit.SECONDS, activity,
                            object : PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
                                override fun onVerificationCompleted(credential: PhoneAuthCredential) {
                                    GlobalScope.launch(CoroutineExceptionHandler { _, t ->
                                        if (instance.mutex.isLocked) instance.mutex.unlock()
                                        continuation.resumeWithException(t)
                                    })
                                    {
                                        signInWithCredential(credential)
                                        releaseInstance()
                                        if (instance.mutex.isLocked) instance.mutex.unlock()
                                        continuation.resume(Unit)
                                    }
                                }

                                override fun onVerificationFailed(p0: FirebaseException) {
                                    if (instance.mutex.isLocked) instance.mutex.unlock()
                                    continuation.resumeWithException(p0)
                                }

                                override fun onCodeSent(verificationId: String, token: PhoneAuthProvider.ForceResendingToken) {
                                    instance.currentVerificationId = verificationId
                                    instance.mResendToken = token
                                    instance.codeSent()
                                    if (instance.mutex.isLocked) instance.mutex.unlock()
                                }
                            }
                    )
                }
            }
        }

        fun onCodeSent(listener: () -> Unit) {
            instance.codeSent = listener
        }

        /**
         * @throws Exception
         */
        private suspend fun signInWithCredential(credential: AuthCredential): AuthResult = FirebaseAuth.getInstance().signInWithCredential(credential).await()
        /**
         * @param smsCode auth code from sms
         * @throws WrongCodeException
         * verificate with current verification id
         */
        suspend fun tryEnterCode(smsCode: String) {
            instance.currentVerificationId?.let {
                try {
                    signInWithCredential(PhoneAuthProvider.getCredential(it, smsCode))
                }
                catch (e:Exception) {
                    throw WrongCodeException()
                }
            } ?: throw Exception("No verification ID")
        }

        fun cancelCurrentVerification() {
            instance.currentContinuation?.cancel()
            instance.currentContinuation = null
        }

        private var INSTANCE: ServerAuth? = null
        private val instance: ServerAuth
        get()  {
            if(INSTANCE == null) {
                INSTANCE = ServerAuth()
            }
            return INSTANCE!!
        }
        private fun releaseInstance() {
            INSTANCE = null
        }
    }
    private var currentVerificationId: String? = null
    private var mResendToken: PhoneAuthProvider.ForceResendingToken? = null
    private var currentContinuation: CancellableContinuation<Unit>? = null
    private val mutex = Mutex()
    private var codeSent: () -> Unit = {}
}