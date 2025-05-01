#include "AESCipher.h"

namespace ROCKSDB_NAMESPACE
{

// Реализация AESBlockCipher
AESBlockCipher::AESBlockCipher(const AESBlockKey& aKey)
    : blockSize_(aKey.keyLength_)
{
    //
    // Note: AES is a bock cipher thus its key length is equal to block
    //       length processed
    const int sKeyLengthInBits = blockSize_ * 8;
    int sRes = 0;
    if ((sRes = AES_set_encrypt_key(aKey.keyBody_.data(),
                                    sKeyLengthInBits,
                                    &aesEncCtx_)) < 0) {
        throw std::runtime_error(std::format("[{0:s}] AES_set_encrypt_key() fails due to the issue [{1:d}]",
                                             __FUNCTION__,
                                             sRes));
    }
    if ((sRes = AES_set_decrypt_key(aKey.keyBody_.data(),
                                    sKeyLengthInBits,
                                    &aesDecCtx_)) < 0) {
        throw std::runtime_error(std::format("[{0:s}] AES_set_decrypt_key() fails due to the issue [{1:d}]",
                                             __FUNCTION__,
                                             sRes));
    }
}

bool AESBlockCipher::ValidateBlockSize(const std::size_t aBlockSize)
{
    return (aBlockSize == 16 || aBlockSize == 24|| aBlockSize == 32);
}

const char* AESBlockCipher::Name() const
{
    return AESBlockCipherName;
}

size_t AESBlockCipher::BlockSize() {
    return blockSize_;
}

Status AESBlockCipher::Encrypt(char* aData)
{
    //
    // Note: OpenSSL AES_encrypt can overlap input and output blocks
    AES_encrypt(reinterpret_cast<const unsigned char*>(aData),
                reinterpret_cast<unsigned char*>(aData),
                &aesEncCtx_);
    return Status::OK();
}

Status AESBlockCipher::Decrypt(char* aData)
{
    //
    // Note: OpenSSL AES_decrypt can overlap input and output blocks
    AES_decrypt(reinterpret_cast<const unsigned char*>(aData),
                reinterpret_cast<unsigned char*>(aData),
                &aesDecCtx_);
    return Status::OK();
}

AESBlockCipherStream::AESBlockCipherStream(AESBlockCipherStream::BlockCipherSptr_t aCipher)
    : cipher_(aCipher)
{
}

size_t AESBlockCipherStream::BlockSize()
{
    return cipher_->BlockSize();
}

void AESBlockCipherStream::AllocateScratch(std::string& aScratch)
{
    aScratch.resize(BlockSize());
}

//
// Note: a bit strange, we probably could use `Encrypt` method of basic class
Status AESBlockCipherStream::Encrypt(uint64_t aFileOffset,
                                     char* aData,
                                     size_t aDataSize)
{
    if (aDataSize % BlockSize() != 0) {
        return Status::InvalidArgument("Data size is not aligned to block size");
    }
    for (std::size_t sOffset = 0; sOffset < aDataSize; sOffset += BlockSize())
    {
        auto sStatus = EncryptBlock(aFileOffset + sOffset / BlockSize(),
                                    aData + sOffset,
                                    nullptr);
        if (!sStatus.ok()) {
            return sStatus;
        }
    }
    return Status::OK();
}

//
// Note: a bit strange, we probably could use `Decrypt` method of basic class
Status AESBlockCipherStream::Decrypt(uint64_t aFileOffset,
                                     char* aData,
                                     size_t aDataSize) {
    if (aDataSize % BlockSize() != 0) {
        return Status::InvalidArgument("Data size is not aligned to block size");
    }
    for (std::size_t sOffset = 0; sOffset < aDataSize; sOffset += BlockSize())
    {
        auto sStatus = DecryptBlock(aFileOffset + sOffset / BlockSize(),
                                    aData + sOffset,
                                    nullptr);
        if (!sStatus.ok()) {
            return sStatus;
        }
    }
    return Status::OK();
}

Status AESBlockCipherStream::EncryptBlock(uint64_t aBlockIndex,
                                          char* aData,
                                          char* aScratch) {
    ///// (void)scratch; // Not used
    return cipher_->Encrypt(aData);
}

Status AESBlockCipherStream::DecryptBlock(uint64_t aBlockIndex,
                                          char* aData,
                                          char* aScratch) {
    ///// (void)aScratch; // Not used
    return cipher_->Decrypt(aData);
}

AESEncryptionProvider::AESEncryptionProvider(const AESBlockKey& aKey)
    : key_(aKey)
{
    if (AESBlockCipher::ValidateBlockSize(key_.keyLength_) == false) {
        throw std::runtime_error(std::format("[{0:s}] improper/unsupported key/block size [{1:d}]",
                                             __FUNCTION__,
                                             key_.keyLength_));
    }
}

const char* AESEncryptionProvider::Name() const
{
    return "AESEncryptionProvider";
}

size_t AESEncryptionProvider::GetPrefixLength() const
{
    return key_.keyLength_;
}

Status AESEncryptionProvider::CreateNewPrefix(const std::string& aFName,
                                              char* aPrefix,
                                              size_t aPrefixLength) const
{
    if (aPrefixLength < key_.keyLength_) {
        return Status::InvalidArgument("Prefix length is too small");
    }
    std::memset(aPrefix, 0, aPrefixLength);
    return Status::OK();
}

Status AESEncryptionProvider::CreateCipherStream(const std::string& aFName,
                                                 const EnvOptions& aOptions,
                                                 Slice& aPrefix,
                                                 BlockAccessCipherStreamPtr_t* aResult)
{
    auto sCipher = std::make_shared<AESBlockCipher>(key_);
    aResult->reset(new AESBlockCipherStream(sCipher));
    return Status::OK();
}

Status AESEncryptionProvider::AddCipher(const std::string& aDescriptor,
                                        const char* aCipher,
                                        size_t aLen,
                                        bool aForWrite)
{
    ///// if (aLen != blockSize_) {
    /////     return Status::InvalidArgument("Invalid cipher length, must match block size");
    ///// }
    /////
    ///// if (aForWrite) {
    /////     writeKey_ = std::string(aCipher, aLen);
    ///// } else {
    /////     readKey_ = std::string(aCipher, aLen);
    ///// }
    ///// return Status::OK();
    return Status::NotSupported();
}

}  // namespace ROCKSDB_NAMESPACE
