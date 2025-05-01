#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <filesystem>
#include <rocksdb/db.h>
#include <AESBlockCipher.h>

template<typename T, typename Serializer, typename Deserializer, std::size_t MaxRawDataSize>
concept DataTranslatorConcept =
  std::invocable<Serializer, const T&, const std::size_t, void*, std::size_t&> &&
  std::invocable<Deserializer, const void*, const std::size_t, const std::size_t, T&>;

template <typename T, typename Serializer, typename Deserializer, std::size_t MaxRawDataSize, std::size_t AlgnmentValue>
    ///// requires DataTranslatorConcept<T, Serializer, Deserializer, MaxRawDataSize>
class PersistentQueue
{
public:
    using Value_t = T;
    using Serializer_t = Serializer;
    using Deserializer_t = Deserializer;

    static constexpr std::size_t QueueMaxElementSize = MaxRawDataSize;
    static constexpr std::size_t DataAlignment = AlgnmentValue;

private:
    static constexpr char HeadKey[] = "HEAD";
    static constexpr char TailKey[] = "TAIL";

public:

    inline PersistentQueue(const std::filesystem::path& aDBFile,
                           const ROCKSDB_NAMESPACE::AESBlockKey& aKey)
        : dbFile_(aDBFile),
          db_(nullptr),
          head_(1),
          tail_(1)
    {
        rocksdb::Options sOptions;
        sOptions.create_if_missing = true;

        if (!aKey.empty()) {
            if (DataAlignment != aKey.keyLength_) {
                throw std::runtime_error(std::format("{0:s} Unexpected/unsupported cipher key lenght, "
                                                     "[{1:d}] is passed but [{2:d}] is expected",
                                                     __FUNCTION__,
                                                     aKey.keyLength_,
                                                     DataAlignment));
            }
            auto sEncryptionProvider = std::make_shared<ROCKSDB_NAMESPACE::AESEncryptionProvider>(aKey);
            auto sBaseEnv = ROCKSDB_NAMESPACE::Env::Default();
            auto sEncryptedEnv = ROCKSDB_NAMESPACE::NewEncryptedEnv(sBaseEnv, sEncryptionProvider);
            sOptions.env = sEncryptedEnv;
        }

        //
        // Open RocksDB
        auto sStatus = rocksdb::DB::Open(sOptions, dbFile_.string(), &db_);
        if (!sStatus.ok()) {
             throw std::runtime_error(std::format("{0:s} rocksdb::DB::Open(\"{1:s}\") failed "
                                                 "due to the issue [{2:s}]",
                                                 __FUNCTION__,
                                                  dbFile_.string(),
                                                  sStatus.ToString()));
        }
        //
        // Load state from RocksDB
        loadCounters();
        //
        // Force to create the DB
        saveCounters();
    }

    inline ~PersistentQueue()
    {
        delete db_;
    }

    PersistentQueue(const PersistentQueue&) = delete;
    PersistentQueue(PersistentQueue&&) = delete;
    PersistentQueue& operator=(const PersistentQueue&) = delete;
    PersistentQueue& operator=(PersistentQueue&&) = delete;

    void enqueue(const Value_t& aValue)
    {
        char sBuff[QueueMaxElementSize];
        std::size_t sBufferSize = QueueMaxElementSize;
        Serializer_t sSerializer{};
        if (sSerializer(aValue,
                        DataAlignment,
                        sBuff,
                        sBufferSize) == false) {
            throw std::runtime_error(std::format("{0:s} Serializer failed",
                                                 __FUNCTION__));
        }
        //
        // Represent integer key value as `std::string`
        const std::string sStrKey = makeKey(tail_);
        //
        // Represent serialized reprezentation of `Value_t` data structure into `std::string`
        const std::string sStrValue(sBuff, sBufferSize);
        //
        // Using of `sync` write property set up to be sure FIFO queue is persistent
        // (well it can impact the performance but everything has its prise)
        rocksdb::WriteOptions sOptions;
        sOptions.sync = true;
        auto sStatus = db_->Put(sOptions, sStrKey, sStrValue);
        if (!sStatus.ok()) {
            throw std::runtime_error(std::format("{0:s} rocksdb::DB::Put(\"{1:s}\") failed due to the issue [{2:s}]",
                                                 __FUNCTION__,
                                                 sStrKey,
                                                 sStatus.ToString()));
        }
        ++tail_;
        saveCounters();
    }

    bool get(Value_t& aValue)
    {
        if (empty()) {
            return false;
        }
        //
        // Represent integral key value as `std::string`
        std::string sStrKey = makeKey(head_);
        std::string sStrValue;
        //
        // Get the value from FIFO queue (represented in `std::string`)
        auto sStatus = db_->Get(rocksdb::ReadOptions(), sStrKey, &sStrValue);
        if (!sStatus.ok()) {
            throw std::runtime_error(std::format("{0:s} rocksdb::DB::Get(\"{1:s}\") failed due to the issue [{2:s}]",
                                                 __FUNCTION__,
                                                 sStrKey,
                                                 sStatus.ToString()));
        }
        //
        // Translate the value from `std::string` into binary format
        const char* sBuffer = sStrValue.data();
        const std::size_t sBufferSize = sStrValue.size();
        //
        // Deserialize the data structure from binary blob
        Deserializer_t sDeserializer{};
        if (sDeserializer(sBuffer,
                          sBufferSize,
                          DataAlignment,
                          aValue) == false) {
            throw std::runtime_error(std::format("{0:s} Deserializer failed",
                                                 __FUNCTION__));
        }
        return true;
    }

    bool pop()
    {
        if (empty()) {
            return false;
        }
        //
        // Represent integral key value as `std::string`
        const std::string sStrKey = makeKey(head_);
        auto sStatus = db_->Delete(rocksdb::WriteOptions(), sStrKey);
        if (!sStatus.ok()) {
            throw std::runtime_error(std::format("{0:s} rocksdb::DB::Delete(\"{1:s}\") failed due to the issue [{2:s}]",
                                                 __FUNCTION__,
                                                 sStrKey,
                                                 sStatus.ToString()));
        }

        ++head_;
        saveCounters();
        return true;
    }

    bool empty() const {
        return head_ >= tail_;
    }

private:

    using Key_t = std::uint64_t;

    static constexpr char HeadCounterKey[] = "meta:HEAD";
    static constexpr char TailCounterKey[] = "meta:TAIL";

    //
    // Keys for stored values
    static std::string makeKey(const Key_t aKeyVal) {
        return std::format("queue:{:020}", aKeyVal);
    }

    //
    // Put counter values (HEAD/TAIL)
    void saveCounters() const
    {
        rocksdb::WriteOptions sOptions;
        sOptions.sync = true;
        const std::string sStrHead(reinterpret_cast<const char*>(&head_), sizeof(head_));
        const std::string sStrTail(reinterpret_cast<const char*>(&tail_), sizeof(tail_));
        auto sStatus = db_->Put(sOptions, HeadCounterKey, sStrHead);
        if (!sStatus.ok()) {
            throw std::runtime_error(std::format("{0:s} rocksdb::DB::Put(\"{1:s}\") failed due to the issue [{2:s}]",
                                                 __FUNCTION__,
                                                 HeadCounterKey,
                                                 sStatus.ToString()));
        }
        sStatus = db_->Put(sOptions, TailCounterKey, sStrTail);
        if (!sStatus.ok()) {
            throw std::runtime_error(std::format("{0:s} rocksdb::DB::Put(\"{1:s}\") failed due to the issue [{2:s}]",
                                                 __FUNCTION__,
                                                 TailCounterKey,
                                                 sStatus.ToString()));
        }
    }

    //
    // Get counter value (HEAD/TAIL)
    void loadCounters()
    {
        std::string sStrHead;
        std::string sStrTail;

        auto sStatus = db_->Get(rocksdb::ReadOptions(), HeadCounterKey, &sStrHead);
        if (!sStatus.ok()) {
            if (!sStatus.IsNotFound()) {
                throw std::runtime_error(std::format("{0:s} rocksdb::DB::Get(\"{1:s}\") failed due to the issue [{2:s}]",
                                                     __FUNCTION__,
                                                     HeadCounterKey,
                                                     sStatus.ToString()));
            }
        } else {
            head_ = *reinterpret_cast<Key_t*>(sStrHead.data());
        }

        sStatus = db_->Get(rocksdb::ReadOptions(), TailCounterKey, &sStrTail);
        if (!sStatus.ok()) {
            if (!sStatus.IsNotFound()) {
                throw std::runtime_error(std::format("{0:s} rocksdb::DB::Get(\"{1:s}\") failed due to the issue [{2:s}]",
                                                     __FUNCTION__,
                                                     TailCounterKey,
                                                     sStatus.ToString()));
            }
        } else {
            tail_ = *reinterpret_cast<Key_t*>(sStrTail.data());
        }
    }

    std::filesystem::path dbFile_;
    rocksdb::DB* db_;
    Key_t head_ = 1;
    Key_t tail_ = 1;
};
