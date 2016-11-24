#include "util/storage.h"

Storage::Storage() {

}

void Storage::PrepareFile(std::string file_name, DATA_TYPE data_type, uint64_t num_prepare_bytes) {

  std::string full_file_name = GetFullFileName(file_name, data_type);

  int fd = open(full_file_name.c_str(), O_RDWR | O_CREAT, S_IRWXU);

  // Stretch the file size to the required size
  if (lseek(fd, num_prepare_bytes, SEEK_SET) == -1) {
    //below is not good practice. See comment for explanation.
    close(fd);
    perror("Error calling lseek() to 'stretch' the file");
    exit(EXIT_FAILURE);
  }

  if (write(fd, "", 1) == -1) {
    close(fd);
    perror("Error writing last byte of the file");
    exit(EXIT_FAILURE);
  }

  close(fd);

  map_mutex.lock();

  file_size_map.emplace(full_file_name, num_prepare_bytes);

  map_mutex.unlock();
}

void Storage::WriteBuckets(std::string file_name, DATA_TYPE data_type, uint32_t buckets_from, uint32_t num_buckets, uint8_t data_to_write[], uint64_t write_pos, uint64_t num_bytes, uint32_t bucket_size) {

  std::string full_file_name = GetFullFileName(file_name, data_type);

  uint64_t num_prepare_bytes = file_size_map[full_file_name];
  if ((write_pos + num_bytes) > num_prepare_bytes) {
    perror("Writing outside file");
    exit(EXIT_FAILURE);
  }

  int fd = open(full_file_name.c_str(), O_WRONLY, S_IRWXU);

  if (lseek(fd, write_pos, SEEK_SET) == -1) {
    //below is not good practice. See comment for explanation.
    close(fd);
    perror("Error calling lseek() to 'stretch' the file");
    exit(EXIT_FAILURE);
  }

  uint64_t q = num_bytes / max_num_write_bytes;
  uint64_t r = num_bytes % max_num_write_bytes;

  for (uint64_t i = 0; i < q; ++i) {

    if (write(fd, data_to_write + i * max_num_write_bytes, max_num_write_bytes) == -1) {
      close(fd);
      perror("Error writing last byte of the file");
      exit(EXIT_FAILURE);
    }
  }

  if (write(fd, data_to_write + q * max_num_write_bytes, r) == -1) {
    close(fd);
    perror("Error writing last byte of the file");
    exit(EXIT_FAILURE);
  }

  close(fd);

  uint64_t bucket_bytes = num_bytes / num_buckets;
  map_mutex.lock();
  for (uint64_t i = 0; i < num_buckets; ++i) {
    filepos_map.emplace(std::make_tuple(full_file_name, buckets_from + i), write_pos + i * bucket_bytes);
    bucket_bytes_map.emplace(std::make_tuple(full_file_name, buckets_from + i), bucket_bytes);
  }

  map_mutex.unlock();
}

void Storage::OverWriteBuckets(std::string file_name, DATA_TYPE data_type, uint32_t buckets_from, uint32_t num_buckets, uint8_t data_to_write[], uint64_t write_pos, uint64_t num_bytes, uint32_t bucket_size) {

  std::string full_file_name = GetFullFileName(file_name, data_type);
  uint64_t bucket_location = filepos_map[std::make_tuple(full_file_name, buckets_from)];
  uint64_t real_write_pos = bucket_location + write_pos;
  uint64_t num_prepare_bytes = file_size_map[full_file_name];
  if ((real_write_pos + num_bytes) > num_prepare_bytes) {
    perror("Writing outside file");
    exit(EXIT_FAILURE);
  }

  int fd = open(full_file_name.c_str(), O_WRONLY, S_IRWXU);

  if (lseek(fd, real_write_pos, SEEK_SET) == -1) {
    //below is not good practice. See comment for explanation.
    close(fd);
    perror("Error calling lseek() to 'stretch' the file");
    exit(EXIT_FAILURE);
  }

  uint64_t q = num_bytes / max_num_write_bytes;
  uint64_t r = num_bytes % max_num_write_bytes;

  for (uint64_t i = 0; i < q; ++i) {

    if (write(fd, data_to_write + i * max_num_write_bytes, max_num_write_bytes) == -1) {
      close(fd);
      perror("Error writing last byte of the file");
      exit(EXIT_FAILURE);
    }
  }

  if (write(fd, data_to_write + q * max_num_write_bytes, r) == -1) {
    close(fd);
    perror("Error writing last byte of the file");
    exit(EXIT_FAILURE);
  }

  close(fd);
}

void Storage::ReadBuckets(std::string file_name, DATA_TYPE data_type, uint32_t buckets_from, uint32_t num_buckets, BYTEArrayVector& res) {

  std::string full_file_name = GetFullFileName(file_name, data_type);

  uint64_t read_location = filepos_map[std::make_tuple(full_file_name, buckets_from)];

  uint64_t num_bytes = bucket_bytes_map[std::make_tuple(full_file_name, buckets_from)];

  res = BYTEArrayVector(num_buckets, num_bytes);

  int fd = open(full_file_name.c_str(), O_RDONLY, S_IRWXU);

  // Move to the specified file position
  if (lseek(fd, read_location, SEEK_SET) == -1) {

    close(fd);
    perror("Error calling lseek() to move into the file");
    exit(EXIT_FAILURE);
  }

  if (read(fd, res.GetArray(), res.size) == -1) {

    close(fd);
    perror("Error reading last byte of the file");
    exit(EXIT_FAILURE);
  }

  close(fd);
}

std::string Storage::GetFullFileName(std::string file_name, DATA_TYPE data_type) {
  std::string full_file_name;
  if (data_type == TABLES) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + TABLES_SUFFIX);
  } else if (data_type == SOLDERINGS) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + SOLDERING_SUFFIX);
  } else if (data_type == AUXDATA) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + AUXDATA_SUFFIX);
  } else if (data_type == VERTICAL_SOLDERINGS) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + VERTICAL_SOLDERINGS_SUFFIX);
  } else if (data_type == AUTHS) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + AUTHS_SUFFIX);
  } else if (data_type == AUTHS_SOLDERINGS) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + AUTHS_SOLDERINGS_SUFFIX);
  } else if (data_type == AUTHS_DELTA_SOLDERINGS) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + AUTHS_DELTA_SOLDERINGS_SUFFIX);
  } else if (data_type == AUTHS_IDS) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + AUTHS_IDS_SUFFIX);
  } else if (data_type == INPUT_MASKS_AUXDATA) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + INPUT_MASKS_AUXDATA_SUFFIX);
  } else if (data_type == INPUT_MASKS_DELTA_AUXDATA) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + INPUT_MASKS_DELTA_AUXDATA_SUFFIX);
  } else if (data_type == INPUT_MASKS_CORRECTIONS) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + INPUT_MASKS_CORRECTIONS_SUFFIX);
  } else if (data_type == INPUT_MASKS_DELTA_CORRECTION) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + INPUT_MASKS_DELTA_CORRECTION_SUFFIX);
  } else if (data_type == INPUT_PERM_BITS) {
    full_file_name =  std::string(STORAGE_PREFIX + file_name + INPUT_PERM_BITS_SUFFIX);
  } else {
    std::cout << "error reading/writing file. Bad filename." << std::endl;
    exit(EXIT_FAILURE);
  }

  return full_file_name;
}