#pragma once

#include <memory>
#include <string>
#include <array>
#include <cstdlib>
#include <rocksdb/env_encryption.h>
#include <rocksdb/status.h>
#include <openssl/aes.h>

namespace ROCKSDB_NAMESPACE {

struct AESBlockKey
{
    //
    // Note: AES algorithm supports the blocks/keys of
    //       following sizes:
    //       * 16 bytes / 128 bits
    //       * 24 bytes / 192 bits
    //       * 32 bytes / 256 bits
    //       Thus `aBlockSize` above can be 16/24/32
    static constexpr std::size_t AESMaxBlockSize = 32;

    using AESKeyBody_t = std::array<unsigned char, AESMaxBlockSize>;

    inline void reset()
    {
        std::memset(keyBody_.data(), 0, keyBody_.size());
        keyLength_ = 0;
    }

    inline bool empty() const
    {
        return keyLength_ == 0;
    }

    AESKeyBody_t keyBody_{};
    std::size_t keyLength_{};
};


// AESBlockCipher: base class for block encryption/decryption
class AESBlockCipher: public BlockCipher
{
public:

    static bool ValidateBlockSize(const std::size_t aBlockSize);

    AESBlockCipher(const AESBlockKey& aKey);
    ~AESBlockCipher() override = default;

    const char* Name() const override;
    size_t BlockSize() override;
    Status Encrypt(char* aData) override;
    Status Decrypt(char* aData) override;

private:

    static constexpr char AESBlockCipherName[] = "AESBlockCipher";

    std::size_t blockSize_;
    AES_KEY aesEncCtx_;
    AES_KEY aesDecCtx_;
};

using AESBlockCipherSptr_t = std::shared_ptr<AESBlockCipher>;

// AESBlockCipherStream: implementation of BlockAccessCipherStream to works with streams
class AESBlockCipherStream: public BlockAccessCipherStream
{
public:
    using BlockCipherSptr_t = std::shared_ptr<BlockCipher>;

    explicit AESBlockCipherStream(BlockCipherSptr_t aCipher);

    size_t BlockSize() override;
    Status Encrypt(uint64_t aFileOffset, char* aData, size_t aDataSize) override;
    Status Decrypt(uint64_t aFileOffset, char* aData, size_t aDataSize) override;

protected:

    void AllocateScratch(std::string& aScratch) override;
    Status EncryptBlock(uint64_t aBlockIndex, char* aData, char* aScratch) override;
    Status DecryptBlock(uint64_t aBlockIndex, char* aData, char* aScratch) override;

private:

    BlockCipherSptr_t cipher_;
};

using BlockAccessCipherStreamPtr_t = std::unique_ptr<BlockAccessCipherStream>;
using AESBlockCipherStreamSptr = std::shared_ptr<AESBlockCipherStream>;

// AESEncryptionProvider: encryption provider for RocksDB
class AESEncryptionProvider: public EncryptionProvider
{
public:

    explicit AESEncryptionProvider(const AESBlockKey& aKey);

    const char* Name() const override;
    size_t GetPrefixLength() const override;
    Status CreateNewPrefix(const std::string& aFName,
                           char* aPrefix,
                           size_t aPrefixLength) const override;
    Status CreateCipherStream(const std::string& aFName,
                              const EnvOptions& aOptions,
                              Slice& aPrefix,
                              BlockAccessCipherStreamPtr_t* aResult) override;
    Status AddCipher(const std::string& aDescriptor,
                     const char* aCipher,
                     size_t aLen,
                     bool aForWrite) override;
private:

    static constexpr char AESEncryptionProviderName[] = "AESEncryptionProvider";

    AESBlockKey key_;
};

}  // namespace ROCKSDB_NAMESPACE
