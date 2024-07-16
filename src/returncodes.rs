pub enum ReturnCodes {
    VerificationSuccess = 1,
    VerificationFailed = 0,
    InvalidContext = -1,
    InvalidInput = -2,
    VerificationFailedWithError = 3,
    SerializationFailed = -4,
    ProvingFailed = -5,
    BufferTooSmall = -0x1000,
}