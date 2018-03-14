/*
 * @author f1est 
 */
 
#ifndef PARSER_H
#define PARSER_H

enum message_read_status_ {
	ALL_DATA_READ = 1,
	MORE_DATA_EXPECTED = 0,
	DATA_CORRUPTED = -1,
	REQUEST_CANCELED = -2,
	DATA_TOO_LONG = -3
};


#endif /* PARSER_H */
