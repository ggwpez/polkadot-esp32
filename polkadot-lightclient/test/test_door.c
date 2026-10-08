#include "../src/door_policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    door_policy_state s = {0};
    uint8_t policy[DOOR_POLICY_LEN] = {'D','O','R','1',1};
    uint8_t allowed[32] = {7}, denied[32] = {8}, zero[32] = {0};
    memcpy(policy+40,allowed,32);
    const uint64_t epoch = 1788620000000ULL;
    assert(!door_policy_scan(&s,allowed,1000));
    assert(door_policy_accept(&s,policy,sizeof policy,100,epoch,epoch,1000));
    assert(!door_policy_scan(&s,denied,1001));
    assert(!door_policy_scan(&s,zero,1002));
    assert(door_policy_scan(&s,allowed,1003));
    assert(door_policy_unlocked(&s,4002));
    assert(!door_policy_unlocked(&s,4003));
    assert(door_policy_scan(&s,allowed,6004));
    policy[4]++; memset(policy+40,0,32);
    assert(door_policy_accept(&s,policy,sizeof policy,101,epoch+1,epoch+1,6005));
    assert(!door_policy_unlocked(&s,6005));
    assert(!door_policy_scan(&s,allowed,6006));
    assert(door_policy_accept(&s,policy,sizeof policy,101,epoch+1,epoch+2,6007));
    assert(s.received_ms == 6005); // A duplicate cannot renew its lease.
    assert(!door_policy_accept(&s,policy,sizeof policy,101,epoch+1,epoch+2,6005+DOOR_MAX_AGE_MS));
    assert(!s.ready);
    assert(!door_policy_accept(&s,policy,sizeof policy,99,epoch+2,epoch+2,6008));
    assert(!door_policy_accept(&s,policy,sizeof policy,102,epoch+2,epoch+DOOR_MAX_AGE_MS+2,6009));
    assert(!door_policy_accept(&s,policy,sizeof policy,102,epoch+6000,epoch,6010));
    assert(!door_policy_accept(&s,policy,sizeof policy,102,epoch+3,0,6011));
    assert(!door_policy_accept(&s,policy,8,102,epoch+3,epoch+3,6012));
    assert(!door_policy_accept(&s,policy,0,102,epoch+3,epoch+3,6013));
    policy[0]='X';
    assert(!door_policy_accept(&s,policy,sizeof policy,102,epoch+3,epoch+3,6014));
    policy[0]='D'; policy[4]=1;
    assert(!door_policy_accept(&s,policy,sizeof policy,102,epoch+3,epoch+3,6015));
    policy[4]=3; memcpy(policy+40,allowed,32);
    assert(door_policy_accept(&s,policy,sizeof policy,102,epoch+3,epoch+30003,0xfffffff0));
    assert(door_policy_scan(&s,allowed,0xfffffff1));
    assert(door_policy_unlocked(&s,20)); // millis rollover
    assert(!door_policy_fresh(&s,DOOR_MAX_AGE_MS-30000)); // Includes 30s already spent on chain
    door_policy_invalidate(&s);
    assert(!door_policy_unlocked(&s,21));
    assert(door_policy_accept(&s,policy,sizeof policy,103,epoch+4,epoch+4,100));
    policy[40]^=1;
    assert(!door_policy_accept(&s,policy,sizeof policy,103,epoch+4,epoch+4,101));
    assert(!s.ready); // Same block with different bytes must fail closed.
    policy[40]^=1;
    assert(door_policy_accept(&s,policy,sizeof policy,104,epoch+4,epoch+5,102));
    assert(s.received_ms == 100); // Elastic scaling can reuse a timestamp.
    assert(!door_policy_accept(&s,policy,sizeof policy,105,epoch+4,epoch+5,100+DOOR_MAX_AGE_MS));
    // Both named keys work; narrowing the policy revokes the other immediately.
    door_policy_state shared = {0};
    uint8_t both[DOOR_POLICY_LEN] = {'D','O','R','1',1};
    memcpy(both+40,allowed,32);
    memcpy(both+72,denied,32);
    uint8_t stranger[32] = {9};
    assert(door_policy_accept(&shared,both,sizeof both,100,epoch,epoch,1000));
    assert(door_policy_scan(&shared,allowed,1001));
    assert(door_policy_scan(&shared,denied,1002));
    assert(door_policy_unlocked(&shared,4001));
    assert(!door_policy_unlocked(&shared,4002));
    assert(!door_policy_scan(&shared,stranger,6003));
    assert(door_policy_scan(&shared,denied,6004));
    both[4]++; memset(both+72,0,32);
    assert(door_policy_accept(&shared,both,sizeof both,101,epoch+1,epoch+1,6005));
    assert(!door_policy_unlocked(&shared,6005));
    assert(!door_policy_scan(&shared,denied,6006));
    assert(door_policy_scan(&shared,allowed,6007));
    assert(!door_policy_scan(&shared,allowed,6005+DOOR_MAX_AGE_MS));
    door_policy_state remote = {0};
    uint8_t toggle[9] = {'D','O','R','2',0,0,0,0,0};
    assert(door_policy_accept(&remote,toggle,9,200,epoch,epoch,1000));
    assert(!door_policy_unlocked(&remote,1001));
    toggle[4]=1; toggle[8]=1;
    assert(door_policy_accept(&remote,toggle,9,201,epoch+1,epoch+1,1002));
    assert(door_policy_unlocked(&remote,1003));
    assert(door_policy_unlocked(&remote,10000)); // Latched beyond the RFID timer.
    assert(!door_policy_scan(&remote,allowed,10001));
    assert(door_policy_unlocked(&remote,10001)); // Tags do not override remote mode.
    assert(door_policy_accept(&remote,toggle,9,201,epoch+1,epoch+2,10002));
    assert(remote.received_ms==1002);
    assert(!door_policy_unlocked(&remote,1002+DOOR_MAX_AGE_MS));
    assert(door_policy_accept(&remote,toggle,9,202,epoch+2,epoch+2,130000));
    door_policy_invalidate(&remote);
    assert(!door_policy_unlocked(&remote,130001));
    toggle[4]=2; toggle[8]=0;
    assert(door_policy_accept(&remote,toggle,9,203,epoch+3,epoch+3,130002));
    assert(!door_policy_unlocked(&remote,130003));
    toggle[8]=2;
    assert(!door_policy_accept(&remote,toggle,9,204,epoch+4,epoch+4,130004));
    assert(!door_policy_accept(&remote,toggle,8,204,epoch+4,epoch+4,130005));
    puts("door policy: RFID and public toggle, freshness, replay, malformed state and rollover passed");
    return 0;
}
