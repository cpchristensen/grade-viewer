#include <stdio.h>
#include <unistd.h>
#include <mhash.h>

#define CREDS_FILENAME "./creds.txt"

#define SHA1_BLOCK_SIZE mhash_get_block_size(MHASH_SHA1)

/* Data types used to store information. */

struct student_t {
	const char* name;
	char grade;
};

struct professor_t {
	char* username;
	char* password;
};

// This function prompts the user for their name and password,
// represented as an integer.
int ReadUserInfo (struct professor_t* prof, const size_t max_size) {
	size_t i;
	int c;

	/* Reads in username. */
	for (i = 0; i < max_size; i += 1) {
		c = getchar();

		if (c == '\n') {
			break;
		} else if (c >= 0 && c < 128){
			prof->username[i] = (char) c;
		} else {
			fprintf(stderr, "ERROR: Invalid character read: %d\n", c);
			return -1;
		}
	}

	/* Reads in password. */
	for (i = 0; i < max_size; i += 1) {
		c = getchar();

		if (c == '\n') {
			break;
		} else if (c >= 0 && c < 128){
			prof->password[i] = (char) c;
		} else {
			fprintf(stderr, "ERROR: Invalid character read: %d\n", c);
			return -1;
		}
	}

	return 0;
}

int createNewUser () {
	size_t i;
	int c;

	const size_t max_string_size = 50;
	char* username = calloc(max_string_size, 1);
	char* password = calloc(max_string_size, 1);

	struct professor_t new_prof = {username, password};

	MHASH td;
	unsigned char hash[SHA1_BLOCK_SIZE];

	FILE* creds_fp;

	/* Opens file for reading and performs error check. */
	creds_fp = fopen(CREDS_FILENAME, "a");
	if (creds_fp == NULL) {
		fprintf(stderr, "ERROR: Could not open credentials file for reading.\n");
		return -1;
	}

	ReadUserInfo(&new_prof, max_string_size);

	fprintf(creds_fp, "%s\n", username);

	/* Hashes provided password. */
	td = mhash_init(MHASH_SHA1);
	if (td == MHASH_FAILED) {
		fprintf(stderr, "ERROR: Failed to hash password.\n");
		return 0;
	}

	mhash(td, password, strlen(password));
	mhash_deinit(td, hash);

	/* Converts hash to hex. */
	for (i = 0; i < SHA1_BLOCK_SIZE; i += 1) {
		fprintf(creds_fp, "%.2x", hash[i]);
	}
	fprintf(creds_fp, "\n");

	puts("Created new user. You may now log in.");

	fclose(creds_fp);

	return 0;
}

// This function simply checks the value of 'password' with the value 123,
// and returns true if they are equal.
int CheckUserPermissionAccess (struct professor_t prof) {
	FILE* creds_fp;

	size_t i;
	ssize_t read;
	char* line;
	size_t line_size;

	int found_username, strings_match;

	MHASH td;
	unsigned char hash[SHA1_BLOCK_SIZE];
	char stringified_hash[SHA1_BLOCK_SIZE * 2];

	line = calloc(50, sizeof(char));

	/* Opens file for reading and performs error check. */
	creds_fp = fopen(CREDS_FILENAME, "r");
	if (creds_fp == NULL) {
		fprintf(stderr, "ERROR: Could not open credentials file for reading.\n");
		return -1;
	}

	found_username = 0;
	for (read = getline(&line, &line_size, creds_fp); read != -1; read = getline(&line, &line_size, creds_fp)) {
		/* Don't need to compare if the strings are not the same size. */
		if (read - 1 != strlen(prof.username)) {
			continue;
		}
		
		/* Checks if the current line matches the username. */
		strings_match = 1;
		for (i = 0; i < strlen(prof.username); i += 1) {
			/* Stops checking after the first wrong character. */
			if (prof.username[i] != line[i]) {
				strings_match = 0;
				break;
			}
		}

		/* Stops after the username has been found. */
		if (strings_match) {
			found_username = 1;
			break;
		}

	}

	/* Username was not found in credentials file. */
	if (!found_username) {
		return 0;
	}

	/* Grabs next line, which is the hashed password. */
	read = getline(&line, &line_size, creds_fp);
	if (read == -1) {
		/* Error reading next line. */
		return 0;
	}

	/* Hashes provided password. */
	td = mhash_init(MHASH_SHA1);
	if (td == MHASH_FAILED) {
		fprintf(stderr, "ERROR: Failed to hash password.\n");
		return 0;
	}

	mhash(td, prof.password, strlen(prof.password));
	mhash_deinit(td, hash);

	/* Converts hash to hex. */
	for (i = 0; i < SHA1_BLOCK_SIZE; i += 1) {
		sprintf(stringified_hash + (2 * i), "%.2x", hash[i]);
	}

	/* Compares with what is stored in file. */
	if ((read - 1) != (SHA1_BLOCK_SIZE * 2)) {
		return 0;
	}
	for (i = 0; i < SHA1_BLOCK_SIZE * 2; i += 1) {
		if (stringified_hash[i] != line[i]) {
			return 0;
		}
	}

	fclose(creds_fp);

	return 1;
}


// This function iterates through the students and their grades, displaying each.
void DisplayStudentInformation (struct student_t* students, size_t n) {
	int i;
	for (i = 0; i < n; i++) {
		printf("%s  %c\n", students[i].name, students[i].grade);
	}
}

// Main program flow.
int main () {
	size_t i;

	size_t line_size;
	char* line;
	ssize_t read;

	const size_t max_string_size = 50;
	struct professor_t prof;
	prof.username = calloc(max_string_size, 1);
	prof.password = calloc(max_string_size, 1);

	const size_t all_students_n = 5;
	struct student_t all_students[all_students_n];

	char choice;

	if (access(CREDS_FILENAME, F_OK ) != -1 ) {
		puts("Credentials file found.");
	} else {
		puts("No Credentials file found, please create at least one new user.");
		createNewUser();
	}

	/* Initializes all students. */
	all_students[0].name = "Julia";
	all_students[0].grade = 'A';

	all_students[1].name = "Tom";
	all_students[1].grade = 'B';

	all_students[2].name = "Ben";
	all_students[2].grade = 'C';

	all_students[3].name = "Alice";
	all_students[3].grade = 'D';

	all_students[4].name = "Ruby";
	all_students[4].grade = 'F';

	printf("Log in (L) or create new user(S)?\n");
	choice = getchar();
	getchar();
	if (choice == 'L') {
		puts("Please enter login credentials:");
		ReadUserInfo(&prof, max_string_size - 1);
	} else if (choice == 'S') {
		puts("Please enter new login credentials:");
		createNewUser();
		puts("Now please re-enter for login");
		ReadUserInfo(&prof, max_string_size - 1);
	} else {
		fprintf(stderr, "Invalid option.\n");
	}

	/* Asks user for login information */

	/* Attempts to log user in. */
	if (CheckUserPermissionAccess(prof)) {
		printf("Login successful.\n");
		puts("Welcome professor. Below are all student grades");
		DisplayStudentInformation(all_students, all_students_n);

		puts("Enter the GPA for students one at a time");
		for (i = 0; i < all_students_n; i++) {
			printf("%s", all_students[i].name);
			scanf(" %c", &all_students[i].grade);
		}

		// Displays new grades and exits.
		puts("You have successfully updated class grades. The grades are now as follows:");
		DisplayStudentInformation(all_students, all_students_n);
	} else {
		printf("Login Failed.\n");
	}

	free(prof.username);
	free(prof.password);

	return 0;
}
