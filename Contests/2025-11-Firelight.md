# Firelight Contest

Firelight Protocol Contest || Firelight Vault: An upgradeable ERC‑4626 compatible vault || Nov 7th, 2025 - Nov 17th, 2025 on [ImmuneFi](https://immunefi.com/audit-competition/)

My Finding Summary

|ID|Title|Severity|
|:-:|:---|:------:|
|[L-01](#l-01-incorrect-timestamp-usage-_in-`periodattimestamp()`-function)|Incorrect Timestamp Usage in `periodAtTimestamp()` Function|LOW|

## L-01 Incorrect Timestamp Usage in `periodAtTimestamp()` Function

### Description

The `periodAtTimestamp()` function contains a fundamental design flaw where it accepts a timestamp parameter but uses the current block timestamp for calculations via the `_sinceEpoch()` helper function. This causes arithmetic underflow when querying future periods after administrators have added future period configurations. While core protocol functionality remains unaffected (all state changing operations use `currentPeriod()` which passes the current timestamp), this vulnerability breaks external integrations, frontend projections, and analytics tools.

### Vulnerability Details and Impact

`periodAtTimestamp()` - The problematic function:
```solidity
    function periodAtTimestamp(uint48 timestamp) public view returns (uint256) {
        PeriodConfiguration memory periodConfiguration = periodConfigurationAtTimestamp(timestamp); //q Uses the passed timestamp to select configuration
        
        return periodConfiguration.startingPeriod + _sinceEpoch(periodConfiguration.epoch) / periodConfiguration.duration; //q _sinceEpoch uses current time, not passed timestamp 
    }
```

`_sinceEpoch()` - The helper function:
```solidity
    function _sinceEpoch(uint48 epoch) private view returns (uint48) {
        return Time.timestamp() - epoch;   //q always uses current block time stamp
    }
```

`periodConfigurationAtTimestamp(timestamp)` correctly selects a configuration based on the passed timestamp, while `_sinceEpoch(epoch)` calculates elapsed time using current block timestamp. If the selected configuration has epoch > Time.timestamp(), arithmetic underflow occurs but this doesn't affect the state changing functions that rely on period calculations as `currentPeriod()` is used.

All state-changing functions that rely on period calculations use `currentPeriod()`, which internally calls `periodAtTimestamp(Time.timestamp())`. Since the passed timestamp is always the current block timestamp, the selected configuration will always have epoch <= Time.timestamp().

### Recommended Fix

The fix is straightforward, use the passed timestamp parameter consistently throughout the calculation instead of mixing it with the current block timestamp.

```solidity
function periodAtTimestamp(uint48 timestamp) public view returns (uint256) {
    PeriodConfiguration memory periodConfiguration = periodConfigurationAtTimestamp(timestamp);
    
    // Validate timestamp is not before epoch
    if (timestamp < periodConfiguration.epoch) revert InvalidPeriod();
    
    // Use passed timestamp instead of current time
    uint48 elapsed = timestamp - periodConfiguration.epoch;
    
    return periodConfiguration.startingPeriod + elapsed / periodConfiguration.duration;
}
```