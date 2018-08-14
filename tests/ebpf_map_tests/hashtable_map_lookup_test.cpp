#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class HashTableMapLookupTest : public ::testing::Test {
      protected:
	struct ebpf_map map;

	virtual void
	SetUp()
	{
		int error;
		uint32_t gkey = 50, gval = 100;

		error =
		    ebpf_map_init(&map, EBPF_MAP_TYPE_HASHTABLE,
				  sizeof(uint32_t), sizeof(uint32_t), 100, 0);
		ASSERT_TRUE(!error);

		error = ebpf_map_update_elem_from_user(&map, &gkey, &gval, 0);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_deinit(&map, NULL);
	}
};

TEST_F(HashTableMapLookupTest, LookupUnexistingEntry)
{
	int error;
	uint32_t key = 51;
	uint32_t value;

	error = ebpf_map_lookup_elem_from_user(&map, &key, &value);

	EXPECT_EQ(ENOENT, error);
}

TEST_F(HashTableMapLookupTest, CorrectLookup)
{
	int error;
	uint32_t key = 50;
	uint32_t value;

	error = ebpf_map_lookup_elem_from_user(&map, &key, &value);

	EXPECT_EQ(0, error);
	EXPECT_EQ(100, value);
}
} // namespace
