#pragma once
#include<switch.h>

struct ResultCode {
 public:
	inline static void AssertOk(Result code);
	
	ResultCode(Result code) : code(code) {}
	inline bool IsOk() {
		return R_SUCCEEDED(code);
	}

	inline bool operator==(const ResultCode &other) const {
		return code == other.code;
	}

	Result code;
};

class ResultError {
 public:
	ResultError(ResultCode code) : code(code) {}
	ResultError(Result code) : code(code) {}
	
	const char *what() const noexcept { return nullptr; }

	const ResultCode code;
};

inline void ResultCode::AssertOk(Result code) {
	if (R_FAILED(code)) {
		throw ResultError(code);
	}
}
