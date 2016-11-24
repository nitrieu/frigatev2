#include "commit/commit-scheme.h"

CommitScheme::CommitScheme(CommonTools& common_tools) :
  common_tools(common_tools),
  code(std::make_unique<ECC>()) { }