#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#ifdef WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

uint32_t GetTickCount()
{
    struct timespec ts;
    unsigned theTick = 0U;
    clock_gettime( 0, &ts );
    theTick  = ts.tv_nsec / 1000000;
    theTick += ts.tv_sec * 1000;
    return theTick;
}

#endif

#include <tomcrypt.h>

#define STRICT_CHECK

typedef struct
{
    uint32_t len;
    const uint8_t str [];
} lpstring;

const int kLengthSize = sizeof(uint32_t);
const int kBlockSize = 16;
const uint8_t luaMagic [] = { 0x1B, 0x4C, 0x75, 0x61, 0x51 };
const uint8_t possibleValidLua [] = { 0x2D, 0x2D };

static bool skipLuaMagic = true;

#define checkTom(X) do { checkTom(X, __FILE__, __LINE__); } while(0)
static void (checkTom)(int result, char *file, unsigned lineno)
{
    if (result == CRYPT_OK) return;
    fprintf(stderr, "%s.%u: %s\n", file, lineno, error_to_string(result));
    exit(1);
}

#define check(X) do { check(X, __FILE__, __LINE__); } while(0)
static void (check)(int result, char *file, unsigned lineno)
{
    if (result) return;
    fprintf(stderr, "%s.%u: %s\n", file, lineno, strerror(errno));
    exit(1);
}

static int cipher_idx = 0;

static void initCipher()
{
	cipher_idx = find_cipher("aes");
	assert(cipher_idx >= 0 && "AES missing!?");
}

static void decipherBuffer(const char *keyStr,
    const uint8_t *in,
	lpstring* cipher_buffer,
	size_t cipher_buffer_size)
{
    uint8_t key[32];
	hash_state md;
    {
		int keyLen = strlen(keyStr);

        checkTom(sha256_init(&md));
        checkTom(sha256_process(&md, (uint8_t*)keyStr, keyLen));
        checkTom(sha256_done(&md, key));
    }

    symmetric_CBC CBC;
    {
        uint8_t IV1[16] = { 0 };
        memset(IV1, 0, sizeof(IV1));
        checkTom(cbc_start(cipher_idx, IV1, key, 32, 0, &CBC));
    }

    checkTom(cbc_decrypt(in, (unsigned char*)cipher_buffer, cipher_buffer_size, &CBC));
    checkTom(cbc_done(&CBC));
}

static long getFileSize(FILE *file)
{
    long pos = ftell(file);
    check(pos != -1);
    check(!fseek(file, 0, SEEK_END));

    long end = ftell(file);
    check(end != -1);
    check(!fseek(file, pos, SEEK_SET));
    return end;
}

static int readFileBinary(FILE *binFile, int size, uint8_t *in)
{
    uint8_t *offset = in;
    int totalRead = 0;
    int readSize = 0;

    do
    {
        readSize = fread(offset, 1, size - totalRead, binFile);
        offset += readSize;
        totalRead += readSize;
    } while (readSize > 0 && totalRead < size);

    return totalRead;
}

bool isValid(const lpstring *out, size_t size)
{
	bool magicPassed = skipLuaMagic || (memcmp(out->str, luaMagic, sizeof(luaMagic)) == 0 && out->len > sizeof(luaMagic));

    return magicPassed &&
		out->len <= size - kLengthSize &&
		out->len > size - kBlockSize;
}

static char** sWords;
static uint32_t sWordCount;

static bool success = false;
static uint32_t num_threads = 1;

bool gatherPasswordListWords(const char* passListPath)
{
	FILE *passList = fopen(passListPath, "rb");
	if (!passList)
	{
		printf("Failed to open: %s\n", passListPath);
		return false;
	}

	size_t passListSize = (size_t)getFileSize(passList);
	char* passListData = (char*)malloc(passListSize + 1);

	check((size_t)readFileBinary(passList, passListSize, (uint8_t*)passListData) == passListSize);

	passListData[passListSize] = 0;

	sWords = (char**)malloc(200000 * sizeof(char*));
	sWordCount = 0;

	char* pch = strtok(passListData, "\r\n");

	while (pch != NULL)
	{
		sWords[sWordCount++] = pch;

		pch = strtok(NULL, "\r\n");
	}

	printf("Gathered [%d] words.\n", sWordCount);

	return true;
}

char* getNextPassword(uint64_t attemptCount)
{
	if (attemptCount < sWordCount)
	{
		return sWords[attemptCount];
	}

	return NULL;
}

lpstring* tryDecipherPassword(const char* password, uint8_t* data, int size)
{
	lpstring* cipher_buffer = (lpstring*)malloc(size);

	decipherBuffer(password, data, cipher_buffer, size);

	if (isValid(cipher_buffer, size))
	{
		return cipher_buffer;
	}

	printf("Decryption failed using password [%s]\n", password);

	return NULL;
}

lpstring* tryDecipherPasswordList(uint8_t* data, int size, uint64_t startAttempt)
{
	uint64_t startedAttempt = startAttempt;
	uint64_t totalAttempts = startAttempt;
	uint64_t ticksPassed = 0;
	int rate = 0;

	int startTickCount = GetTickCount();

	lpstring* cipher_buffer = (lpstring*)malloc(kBlockSize); // Small size first, for speeeed.

	while (true)
	{
		const char* newPassword = getNextPassword(totalAttempts);

		if (newPassword == NULL || success)
		{
			break;
		}

		totalAttempts += num_threads;

		decipherBuffer(newPassword, data, cipher_buffer, kBlockSize);

		if (isValid(cipher_buffer, size))
		{
			printf("Succeeded with word: [%s] on attempt [%" PRId64 "]\n", newPassword, totalAttempts);

			free(cipher_buffer);
			cipher_buffer = (lpstring*)malloc(size); // Now for full decryption.

			decipherBuffer(newPassword, data, cipher_buffer, size);

			return cipher_buffer;
		}

		if (totalAttempts % (10000000 * num_threads) == startedAttempt)
		{
			ticksPassed = GetTickCount() - startTickCount;
			rate = ticksPassed > 0 ? (totalAttempts / num_threads) / ticksPassed : 0;

			printf("[%" PRId64 "] Attempt [%" PRId64 "] | Ticks [%" PRId64 "] | Rate [%d]\n", startedAttempt, totalAttempts, ticksPassed, rate);
		}
	}

	ticksPassed = GetTickCount() - startTickCount;
	rate = ticksPassed > 0 ? totalAttempts / ticksPassed : 0;

	printf("[%" PRId64 "] Total attempts: [%" PRId64 "] | Ticks: [%" PRId64 "] | Eff. Rate [%d]\n", startedAttempt, totalAttempts, ticksPassed, rate);

	return NULL;
}

uint8_t *encrypted_file = NULL;
size_t encrypted_size = 0;
char* out_path = NULL;

void* threadedDecryptFunc(void *arg)
{
	uint64_t thread_index = (uint64_t)arg;

	printf("Started thread with thread_index: %d\n", (int)thread_index);

	lpstring* out = tryDecipherPasswordList(encrypted_file, encrypted_size, thread_index);

	if (out != NULL && !success)
	{
		success = true;

		printf("Decryption successful!\n");
		FILE *outFile = fopen(out_path, "wb");
		check(!!outFile);
		check(fwrite(out->str, 1, out->len, outFile) == out->len);
		check(!fclose(outFile));

		free(out);
	}

#ifndef WIN32
	pthread_exit(NULL);
#endif

	return NULL;
}

void perform_decryption(char* password, bool isList)
{
	initCipher();

	lpstring *out = NULL;
	
	if (!isList)
	{
		out = tryDecipherPassword(password, encrypted_file, encrypted_size);
	}
	else
	{
		if (!gatherPasswordListWords(password))
		{
			return;
		}

#ifndef WIN32
		if (num_threads > 1)
		{
			pthread_t threads[num_threads];
			uint64_t i;

			for (i = 0; i < num_threads; i++)
				pthread_create(threads + i, NULL, threadedDecryptFunc, (void*)i);

			for (i = 0; i < num_threads; i++)
				pthread_join(threads[i], NULL);

			return;
		}
#endif

		out = tryDecipherPasswordList(encrypted_file, encrypted_size, 0);
	}

	if (out != NULL)
	{
		success = true;

		printf("Decryption successful!\n");
		FILE *outFile = fopen(out_path, "wb");
		check(!!outFile);
		check(fwrite(out->str, 1, out->len, outFile) == out->len);
		check(!fclose(outFile));
	}
}

int main(int argc, char **argv)
{
	if (argc < 5 || (strcmp(argv[1], "-d") && strcmp(argv[1], "-dl"))) {
		fprintf(stderr, "Syntax: %s <-d | -dl> <password | passwordList> <input> <output>\n", argv[0]);
		return 0;
	}

	if (!strcmp(argv[3], argv[4])) {
		fprintf(stderr, "Refusing to overwrite input\n");
		return 0;
	}

	bool isPasswordList = false;

	if (!strcmp(argv[1], "-dl"))
	{
		isPasswordList = true; // Decrypt with password list
	}

#ifndef WIN32
	if (argc > 5)
	{
		num_threads = atoi(argv[5]);
	}
#endif

	out_path = argv[4];

	checkTom(register_cipher(&aes_desc));

	FILE *encFile = fopen(argv[3], "rb");
	check(!!encFile);
	encrypted_size = (size_t)getFileSize(encFile);

	if (!encrypted_size) {
		fprintf(stderr, "Refusing to decrypt empty file\n");
		check(!fclose(encFile));
		return 0;
	}

	encrypted_file = (uint8_t *)malloc(encrypted_size);
	check((size_t)readFileBinary(encFile, encrypted_size, encrypted_file) == encrypted_size);
	check(!fclose(encFile));
	
	perform_decryption(argv[2], isPasswordList);

    free(encrypted_file);

	printf("Press any key to exit...\n");

	getchar();

    return 0;
}
