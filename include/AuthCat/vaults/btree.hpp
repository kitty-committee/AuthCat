#ifndef VAULTS_BTREE_HPP
#define VAULTS_BTREE_HPP

#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string>

#define SHA256_HASH_NAME "SHA256"

namespace nathcat {
namespace vaults {
/**
 * @brief Perform a SHA256 hash operation on a given string, outputting the
 * result to a given buffer. Internally uses EVP_Q_digest.
 *
 * @param str The string to hash
 * @param buffer The buffer to output the hash to
 * @param buflen The final length of the outputted hash, should always be 32
 * bytes.
 */
inline int sha256_hash(char *str, unsigned char buffer[SHA256_DIGEST_LENGTH],
                       size_t *buflen) {
  return EVP_Q_digest(NULL, SHA256_HASH_NAME, NULL, str, strlen(str), buffer,
                      buflen);
}

/**
 * @class BTreeNode
 * @brief Represents a node inside the file BTree. By its' nature also forms the
 * BTree itself.
 *
 */
class BTreeNode {
public:
  /**
   * @brief The SHA256 hashed name of the file this node represents
   */
  unsigned char name[SHA256_DIGEST_LENGTH];
  /**
   * @brief The offset of the target file through the node.
   */
  unsigned int offset = 0;
  /**
   * @brief The left child of this node
   */
  BTreeNode *leftChild = nullptr;
  /**
   * @brief The right child of this node
   */
  BTreeNode *rightChild = nullptr;

  inline bool operator>(BTreeNode &other) { return *this > other.name; }

  inline bool operator>(unsigned char name[SHA256_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      if (this->name[i] > name[i])
        return true;
    }

    return false;
  }

  inline bool operator==(BTreeNode &other) { return *this == other.name; }

  inline bool operator==(unsigned char name[SHA256_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      if (this->name[i] != name[i])
        return false;
    }

    return true;
  }

  inline bool operator<(BTreeNode &other) { return *this < other.name; }

  inline bool operator<(unsigned char name[SHA256_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      if (this->name[i] < name[i])
        return true;
    }

    return false;
  }

  /**
   * @brief Insert a new node into the tree
   *
   * @param node The node to insert
   */
  inline void insert(BTreeNode *node) {
    if (*this == *node) {
      node->leftChild = this->leftChild;
      this->leftChild = node;
    } else if (*node < *this) {
      if (this->leftChild != nullptr) {
        this->leftChild->insert(node);
      } else {
        this->leftChild = node;
      }
    } else {
      if (this->rightChild != nullptr) {
        this->rightChild->insert(node);
      } else {
        this->rightChild = node;
      }
    }
  }

  /**
   * @brief Search the sub-tree of this node for a specific file name
   *
   * @param name The name to search for
   * @return The node of the searched file, if any match. If none match,
   * nullptr.
   */
  inline BTreeNode *search(std::string name) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    size_t hashlen = 0;
    sha256_hash(name.data(), hash, &hashlen);

    return search(hash);
  }

  /**
   * @brief Search the sub-tree of this node for a file by its hash
   *
   * @param hash The hash to search for
   * @return The node of the searched file, if any match. If none match,
   * nullptr.
   */
  inline BTreeNode *search(unsigned char hash[SHA256_DIGEST_LENGTH]) {
    if (*this == hash) {
      return this;
    } else if (*this > hash) {
      if (this->leftChild == nullptr)
        return nullptr;
      return this->leftChild->search(hash);
    } else {
      if (this->rightChild == nullptr)
        return nullptr;
      return this->rightChild->search(hash);
    }
  }
};

} // namespace vaults
} // namespace nathcat

#endif
